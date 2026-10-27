use std::collections::BTreeSet;
use std::fmt::Display;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use opca_acme_api::{Enrolment, EnrolmentOffer, ErrorBody, ErrorKind, IssuanceConfig, Status};
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use wslib_crypto_x509::{CertificateView, NameSubtree, inspect, pem};
use wslib_pairing::{CodeError, PairingCode, Redemption};

use crate::enrolled::operator_config;
use crate::{Broker, Error};

/// `redeem` waits for ever on a held lock; uncontended it takes milliseconds.
/// This sits well inside the listener's 10 s drain and a client's patience.
const REDEEM_TIMEOUT: Duration = Duration::from_secs(5);

/// Whether the broker is waiting to pair, or paired with an opCA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    Enrolling,
    Enrolled(Enrolled),
}

/// What an accepted enrolment left in the state directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrolled {
    /// The subordinate first, then the root.
    pub chain_pem: String,
    pub operator_pin: String,
    pub config: IssuanceConfig,
    /// The API key's pin as the pairing URI gave it to opCA.
    pub api_pin: String,
    #[serde(default)]
    pub revoked: bool,
}

fn enrolment_path(state: &Path) -> PathBuf {
    state.join("enrolment.json")
}

struct Checked {
    code: PairingCode,
    enrolled: Enrolled,
    operator: Arc<ServerConfig>,
}

pub(crate) fn load(state: &Path) -> Result<Mode, Error> {
    let path = enrolment_path(state);
    match std::fs::read(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Mode::Enrolling),
        read => {
            let enrolled =
                serde_json::from_slice(&read?).map_err(|e| format!("{}: {e}", path.display()))?;
            Ok(Mode::Enrolled(enrolled))
        }
    }
}

impl Broker {
    pub(crate) fn enrolment_path(&self) -> PathBuf {
        enrolment_path(&self.state)
    }

    /// What `GET /v1/enrolment` answers; `None` once enrolled.
    pub fn offer(&self) -> Option<EnrolmentOffer> {
        (self.mode() == Mode::Enrolling).then(|| EnrolmentOffer {
            csr_pem: self.subordinate.csr_pem().into(),
            host: self.host.clone(),
            configured_domains: self.domains.clone(),
            versions: self.versions(),
        })
    }

    /// Checks `enrolment` whole, then redeems its code and, if accepted,
    /// stores it; a refusal before the redeem costs no attempt.
    pub async fn enrol(self: Arc<Self>, enrolment: Enrolment) -> Result<Status, ErrorBody> {
        let checked = self.check(enrolment)?;
        let enrolled = checked.enrolled.clone();
        let broker = self.clone();
        let redeeming = tokio::task::spawn_blocking(move || broker.redeem_and_store(checked));
        match tokio::time::timeout(REDEEM_TIMEOUT, redeeming).await {
            Ok(Ok(stored)) => stored.and_then(|()| self.status(&enrolled)),
            Ok(Err(panicked)) => Err(internal(panicked)),
            Err(_) => Err(internal("timed out waiting for the pairing code's lock")),
        }
    }

    fn check(&self, enrolment: Enrolment) -> Result<Checked, ErrorBody> {
        let code = enrolment
            .code
            .parse::<PairingCode>()
            .map_err(|_| bad_request("the code is not a pairing code"))?;
        let pin = &enrolment.operator_pin;
        if pin.len() != 64 || !pin.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(bad_request(
                "the operator pin is not 64 lower-case hex digits",
            ));
        }
        let (subordinate, root) = self.check_chain(&enrolment.chain_pem)?;
        self.check_config(&enrolment.config, &subordinate)?;
        let operator =
            operator_config(&self.provider, &self.serving, root, pin).map_err(bad_request)?;
        let enrolled = Enrolled {
            chain_pem: enrolment.chain_pem,
            operator_pin: enrolment.operator_pin,
            config: enrolment.config,
            api_pin: self.pin().to_string(),
            revoked: false,
        };
        Ok(Checked {
            code,
            enrolled,
            operator,
        })
    }

    pub(crate) fn check_chain(
        &self,
        chain_pem: &str,
    ) -> Result<(CertificateView, CertificateDer<'static>), ErrorBody> {
        let chain = pem::certificates(chain_pem).map_err(bad_request)?;
        let [subordinate, .., root] = &chain[..] else {
            return Err(bad_request(
                "the chain needs the subordinate, then the root",
            ));
        };
        let root_der = root.clone();
        let (subordinate, root) = (
            inspect(subordinate).map_err(bad_request)?,
            inspect(root).map_err(bad_request)?,
        );
        if subordinate.spki != self.subordinate.spki() {
            return Err(bad_request(
                "the chain's first certificate is not for this broker's key",
            ));
        }
        if !subordinate.ca || !root.self_signed || subordinate.issuer != root.subject {
            return Err(bad_request(
                "the chain is not a subordinate CA followed by the root that issued it",
            ));
        }
        if subordinate.not_after <= SystemTime::now() {
            return Err(bad_request("the subordinate has expired"));
        }
        Ok((subordinate, root_der))
    }

    pub(crate) fn check_config(
        &self,
        config: &IssuanceConfig,
        subordinate: &CertificateView,
    ) -> Result<(), ErrorBody> {
        let lowercase = |names: &[String]| -> BTreeSet<String> {
            names.iter().map(|n| n.to_ascii_lowercase()).collect()
        };
        let permitted = lowercase(&config.permitted_domains);
        let constrained: BTreeSet<String> = subordinate
            .name_constraints
            .iter()
            .flat_map(|constraints| &constraints.permitted)
            .filter_map(|subtree| match subtree {
                NameSubtree::Dns(name) => Some(name.to_ascii_lowercase()),
                _ => None,
            })
            .collect();
        let refusal = if permitted.is_empty() {
            "the config permits no domains"
        } else if permitted != constrained {
            "the config's domains are not those the subordinate's name constraints permit"
        } else if !host_within(&self.host, &config.permitted_domains) {
            "the broker's host is not a name within the permitted domains, and step-ca's own \
             TLS certificate is issued for it"
        } else if !self.domains.is_empty() && permitted != lowercase(&self.domains) {
            "the config's domains are not those configured on the broker"
        } else if config.leaf_days == 0 || config.leaf_days > config.leaf_max_days {
            "leaf_days must be at least 1 and at most leaf_max_days"
        } else if config.challenges.is_empty() {
            "the config allows no challenges"
        } else {
            return Ok(());
        };
        Err(bad_request(refusal))
    }

    /// Staged before the redeem, so that an accepted code cannot meet a failed write.
    fn redeem_and_store(&self, checked: Checked) -> Result<(), ErrorBody> {
        let _one_at_a_time = self.changing.lock().unwrap_or_else(|e| e.into_inner());
        let json = serde_json::to_vec_pretty(&checked.enrolled).map_err(internal)?;
        let staged = wslib_file_atomic::Options::new()
            .stage(&self.enrolment_path(), &json)
            .map_err(internal)?;
        let redeemed = self.code.redeem(&checked.code);
        let Ok(Redemption::Accepted) = redeemed else {
            let _ = staged.discard();
            return Err(refusal(redeemed));
        };
        staged.promote().map_err(internal)?;
        *self.mode.write().unwrap_or_else(|e| e.into_inner()) = Mode::Enrolled(checked.enrolled);
        self.tls.reload(checked.operator);
        tracing::info!("enrolled; the API now requires the operator's client certificate");
        self.on_new_chain();
        Ok(())
    }
}

fn refusal(redeemed: Result<Redemption, CodeError>) -> ErrorBody {
    let refused = |kind, message: String| ErrorBody { kind, message };
    match redeemed {
        Ok(Redemption::Refused { remaining }) => refused(
            ErrorKind::WrongCode { remaining },
            "wrong pairing code".into(),
        ),
        Ok(Redemption::Spent(by)) => refused(
            ErrorKind::CodeSpent,
            format!("the pairing code is spent ({by:?})"),
        ),
        Ok(other) => internal(format!("unexpected redemption {other:?}")),
        Err(e) => internal(e),
    }
}

/// Whether `host` is a DNS name equal to or under one of `domains`.
pub(crate) fn host_within(host: &str, domains: &[String]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host.parse::<std::net::IpAddr>().is_err()
        && domains.iter().any(|domain| {
            let domain = domain.to_ascii_lowercase();
            host == domain || host.ends_with(&format!(".{domain}"))
        })
}

pub(crate) fn bad_request(message: impl Display) -> ErrorBody {
    ErrorBody {
        kind: ErrorKind::BadRequest,
        message: message.to_string(),
    }
}

pub(crate) fn internal(error: impl Display) -> ErrorBody {
    tracing::error!(%error, "enrolment failed");
    ErrorBody {
        kind: ErrorKind::Internal,
        message: error.to_string(),
    }
}

pub(crate) fn decimal(hex: &str) -> String {
    let mut digits = vec![0u32];
    for nibble in hex.chars().filter_map(|c| c.to_digit(16)) {
        let mut carry = nibble;
        for digit in &mut digits {
            let value = *digit * 16 + carry;
            (*digit, carry) = (value % 10, value / 10);
        }
        while carry > 0 {
            digits.push(carry % 10);
            carry /= 10;
        }
    }
    while digits.len() > 1 && digits.last() == Some(&0) {
        digits.pop();
    }
    digits
        .iter()
        .rev()
        .map(|d| char::from(b'0' + *d as u8))
        .collect()
}

pub(crate) fn rfc_3339(at: SystemTime) -> String {
    let seconds = at
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let (days, time) = ((seconds / 86_400) as i64, seconds % 86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time / 3600,
        time % 3600 / 60,
        time % 60
    )
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 to a proleptic Gregorian date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u32;
    (year_of_era + era * 400 + i64::from(month <= 2), month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_must_be_a_name_within_the_domains() {
        let domains = ["home.example".to_string()];
        assert!(host_within("home.example", &domains));
        assert!(host_within("ACME.Home.Example.", &domains));
        assert!(!host_within("acme.lab.example", &domains));
        assert!(!host_within("evilhome.example", &domains));
        assert!(!host_within("10.0.0.5", &domains));
        assert!(!host_within("::1", &domains));
    }

    #[test]
    fn serials_read_as_decimal() {
        assert_eq!(decimal("00"), "0");
        assert_eq!(decimal("0100"), "256");
        assert_eq!(decimal("7fffffffffffffffffff"), "604462909807314587353087");
    }

    #[test]
    fn times_are_utc_rfc_3339() {
        let at = |seconds| UNIX_EPOCH + Duration::from_secs(seconds);
        assert_eq!(rfc_3339(at(0)), "1970-01-01T00:00:00Z");
        assert_eq!(rfc_3339(at(1_900_000_000)), "2030-03-17T17:46:40Z");
        assert_eq!(rfc_3339(at(951_782_400)), "2000-02-29T00:00:00Z");
    }
}
