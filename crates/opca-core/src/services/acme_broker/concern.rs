use chrono::{DateTime, Utc};
use serde::Serialize;

use super::api::IssuerState;
use crate::services::database::models::{Broker, BrokerState};
use crate::utils::datetime::{DateTimeFormat, parse_datetime};

const EXPIRY_WARNING_DAYS: i64 = 30;
/// One missed four-weekly signing session, plus a week.
const SILENT_AFTER_DAYS: i64 = 35;

/// Why an active broker wants the operator's attention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "concern", rename_all = "snake_case")]
pub enum Concern {
    /// Negative once expired.
    Expiring {
        days: i64,
    },
    Silent {
        days: i64,
    },
    /// Signed, but the broker has never taken it.
    NotDelivered,
    /// The operator paused its issuance.
    Paused,
}

impl std::fmt::Display for Concern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::Expiring { days } if days < 0 => write!(f, "expired {} days ago", -days),
            Self::Expiring { days } => write!(f, "expires in {days} days"),
            Self::Silent { days } => write!(f, "not heard from in {days} days"),
            Self::NotDelivered => f.write_str("signed, not delivered"),
            Self::Paused => f.write_str("issuance paused"),
        }
    }
}

pub fn concerns(broker: &Broker, now: DateTime<Utc>) -> Vec<Concern> {
    if broker.state != BrokerState::Active || broker.url.is_none() {
        return Vec::new();
    }
    let days_since = |stored: &Option<String>| {
        let at = parse_datetime(stored.as_deref()?, DateTimeFormat::Openssl).ok()?;
        Some((now - at).num_days())
    };
    let mut found = Vec::new();
    if let Some(days) = days_since(&broker.expiry_date).map(|d| -d)
        && days <= EXPIRY_WARNING_DAYS
    {
        found.push(Concern::Expiring { days });
    }
    match days_since(&broker.last_contact) {
        None => found.push(Concern::NotDelivered),
        Some(days) if days > SILENT_AFTER_DAYS => found.push(Concern::Silent { days }),
        Some(_) => {}
    }
    if broker.issuer_state == Some(IssuerState::Paused) {
        found.push(Concern::Paused);
    }
    found
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;
    use crate::utils::datetime::format_datetime;

    fn at(now: DateTime<Utc>, days: i64) -> Option<String> {
        Some(format_datetime(
            now + Duration::days(days),
            DateTimeFormat::Openssl,
        ))
    }

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(Utc::now().timestamp(), 0).unwrap()
    }

    fn broker(now: DateTime<Utc>, expires_in: i64, contacted_ago: Option<i64>) -> Broker {
        Broker {
            id: 1,
            subordinate_serial: "2".into(),
            url: Some("https://acme.home.arpa:9443".into()),
            pinned_key: Some("ab".repeat(32)),
            permitted_domains: vec!["home.arpa".into()],
            state: BrokerState::Active,
            last_contact: contacted_ago.and_then(|d| at(now, -d)),
            created_at: String::new(),
            updated_at: String::new(),
            cn: Some("acme.home.arpa".into()),
            expiry_date: at(now, expires_in),
            issuer_state: Some(IssuerState::Issuing),
        }
    }

    #[test]
    fn a_healthy_broker_raises_nothing() {
        let now = now();
        assert!(concerns(&broker(now, 60, Some(3)), now).is_empty());
        assert!(concerns(&broker(now, 31, Some(35)), now).is_empty());
    }

    #[test]
    fn expiry_within_30_days_silence_past_35_and_no_delivery_are_flagged() {
        let now = now();
        assert_eq!(
            concerns(&broker(now, 30, Some(36)), now),
            [Concern::Expiring { days: 30 }, Concern::Silent { days: 36 }]
        );
        assert_eq!(
            concerns(&broker(now, -2, None), now),
            [Concern::Expiring { days: -2 }, Concern::NotDelivered]
        );
    }

    #[test]
    fn a_paused_broker_is_flagged_and_one_never_asked_is_not() {
        let now = now();
        let with = |issuer_state| Broker {
            issuer_state,
            ..broker(now, 60, Some(3))
        };
        assert_eq!(
            concerns(&with(Some(IssuerState::Paused)), now),
            [Concern::Paused]
        );
        assert!(concerns(&with(None), now).is_empty());
        assert_eq!(Concern::Paused.to_string(), "issuance paused");
    }

    #[test]
    fn revoked_and_hand_signed_subordinates_are_not_watched() {
        let now = now();
        let revoked = Broker {
            state: BrokerState::Revoked,
            ..broker(now, 1, None)
        };
        let by_hand = Broker {
            url: None,
            ..broker(now, 1, None)
        };
        assert!(concerns(&revoked, now).is_empty());
        assert!(concerns(&by_hand, now).is_empty());
    }

    #[test]
    fn each_concern_reads_as_a_phrase() {
        assert_eq!(
            Concern::Expiring { days: -3 }.to_string(),
            "expired 3 days ago"
        );
        assert_eq!(
            Concern::Silent { days: 40 }.to_string(),
            "not heard from in 40 days"
        );
    }
}
