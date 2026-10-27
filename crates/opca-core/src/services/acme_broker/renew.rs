use opca_acme_api::{ChainUpdate, IssuanceConfig, Status};
use serde::Serialize;

use super::{BrokerClient, BrokerError, Endpoint};
use crate::error::OpcaError;
use crate::op::Runner;
use crate::services::ca::CertificateAuthority;
use crate::services::ca::operator::Operator;
use crate::services::ca::subordinate::{permitted_domains, same_domains};
use crate::services::database::models::{Broker, BrokerState};

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Renewal {
    Renewed {
        serial: String,
        status: Status,
    },
    /// Nothing signed: the broker now asks for other domains, which renewing
    /// with `change_domains` confirms.
    DomainsChanged {
        recorded: Vec<String>,
        configured: Vec<String>,
    },
    /// Nothing signed.
    Unreachable {
        error: BrokerError,
    },
    /// Signed and recorded, but the broker kept its old chain; renewing again
    /// signs afresh.
    NotDelivered {
        serial: String,
        error: BrokerError,
    },
    Failed {
        error: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct BrokerRenewal {
    pub id: i64,
    #[serde(flatten)]
    pub renewal: Renewal,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "notice", rename_all = "snake_case")]
pub enum BrokerNotice {
    Told { status: Status },
    NotTold { error: BrokerError },
}

#[derive(Debug, Clone, Serialize)]
pub struct BrokerRevocation {
    pub broker: Broker,
    #[serde(flatten)]
    pub notice: BrokerNotice,
}

/// The broker's configured domains when they differ from those recorded.
fn changed_domains(
    recorded: &[String],
    configured: &[String],
) -> Result<Option<Vec<String>>, OpcaError> {
    if configured.is_empty() {
        return Ok(None);
    }
    let configured = permitted_domains(configured)?;
    Ok((!same_domains(recorded, &configured)).then_some(configured))
}

impl<R: Runner> CertificateAuthority<R> {
    pub fn renew_broker(
        &mut self,
        operator: &Operator,
        id: i64,
        change_domains: bool,
    ) -> Result<Renewal, OpcaError> {
        let broker = self.broker(id)?;
        let renewal = self.renew_at(operator, &broker, change_domains);
        self.store_ca_database()?;
        Ok(renewal)
    }

    /// Renews every active broker, reporting each, so one that cannot be
    /// reached is never passed over in silence.
    pub fn renew_all_brokers(
        &mut self,
        operator: &Operator,
    ) -> Result<Vec<BrokerRenewal>, OpcaError> {
        let brokers = self.list_subordinates()?;
        let mut renewals = Vec::new();
        for broker in brokers
            .iter()
            .filter(|b| b.state == BrokerState::Active && b.url.is_some())
        {
            renewals.push(BrokerRenewal {
                id: broker.id,
                renewal: self.renew_at(operator, broker, false),
            });
        }
        self.store_ca_database()?;
        Ok(renewals)
    }

    fn renew_at(&mut self, operator: &Operator, broker: &Broker, change_domains: bool) -> Renewal {
        match self.try_renew(operator, broker, change_domains) {
            Ok(renewal) => renewal,
            // Only the calls made before anything is signed surface a broker error here.
            Err(OpcaError::Broker(error)) => Renewal::Unreachable { error },
            Err(e) => Renewal::Failed {
                error: e.to_string(),
            },
        }
    }

    fn try_renew(
        &mut self,
        operator: &Operator,
        broker: &Broker,
        change_domains: bool,
    ) -> Result<Renewal, OpcaError> {
        let client = BrokerClient::new(Endpoint::of_broker(broker)?, Some(operator))?;
        let current = client.status()?;
        let fresh = client.fresh_csr()?;
        self.contacted(broker.id)?;

        let domains = changed_domains(&broker.permitted_domains, &fresh.configured_domains)?;
        if let (Some(configured), false) = (&domains, change_domains) {
            return Ok(Renewal::DomainsChanged {
                recorded: broker.permitted_domains.clone(),
                configured: configured.clone(),
            });
        }
        let signed = self.renew_subordinate(
            broker.id,
            fresh.csr_pem.as_bytes(),
            domains.as_deref(),
            change_domains,
            None,
        )?;
        let serial = signed.broker.subordinate_serial;
        let update = ChainUpdate {
            chain_pem: self.chain_of(&signed.cert_pem)?,
            config: IssuanceConfig {
                permitted_domains: signed.broker.permitted_domains,
                ..current.config
            },
        };
        let status = match client.put_chain(&update) {
            Ok(status) => status,
            Err(error) => return Ok(Renewal::NotDelivered { serial, error }),
        };
        self.contacted(broker.id)?;
        Ok(Renewal::Renewed { serial, status })
    }

    /// Revokes subordinate `id` through the root, then tells its broker to
    /// stop issuing. The revocation stands whether or not the broker hears of
    /// it; revoking again only tells the broker. The caller regenerates the
    /// CRL, as after any revoke.
    pub fn revoke_broker(
        &mut self,
        operator: &Operator,
        id: i64,
    ) -> Result<BrokerRevocation, OpcaError> {
        let broker = self.broker(id)?;
        let client = BrokerClient::new(Endpoint::of_broker(&broker)?, Some(operator))?;
        let broker = match broker.state {
            BrokerState::Active => self.revoke_subordinate(id)?,
            BrokerState::Revoked => broker,
        };
        let notice = match client.revoke() {
            Ok(status) => {
                self.contacted(id)?;
                self.store_ca_database()?;
                BrokerNotice::Told { status }
            }
            Err(error) => BrokerNotice::NotTold { error },
        };
        Ok(BrokerRevocation { broker, notice })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    #[test]
    fn only_a_broker_asking_for_other_domains_has_changed() {
        let recorded = names(&["home.arpa", "lab.example"]);
        for unchanged in [&[][..], &["LAB.example", "home.arpa"]] {
            assert_eq!(changed_domains(&recorded, &names(unchanged)).unwrap(), None);
        }
        assert_eq!(
            changed_domains(&recorded, &names(&["home.arpa"])).unwrap(),
            Some(names(&["home.arpa"]))
        );
        assert!(changed_domains(&recorded, &names(&["*.home.arpa"])).is_err());
    }
}
