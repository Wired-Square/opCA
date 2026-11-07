use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

use crate::services::database::models::BrokerCert;
use crate::utils::datetime::{DateTimeFormat, parse_datetime};

/// Past this, an expired leaf is taken to belong to something decommissioned.
const FORGOTTEN_AFTER_DAYS: i64 = 14;

/// A broker's leaf that its ACME client should have renewed by now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LeafDue {
    pub broker_id: i64,
    pub serial: String,
    pub name: String,
    /// Negative once expired.
    pub days: i64,
}

struct Leaf<'c> {
    cert: &'c BrokerCert,
    names: BTreeSet<String>,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

impl<'c> Leaf<'c> {
    fn of(cert: &'c BrokerCert) -> Option<Self> {
        let at = |stamp: &str| parse_datetime(stamp, DateTimeFormat::Openssl).ok();
        Some(Self {
            cert,
            names: cert.sans.iter().map(|n| n.to_ascii_lowercase()).collect(),
            not_before: at(&cert.not_before)?,
            not_after: at(&cert.not_after)?,
        })
    }

    /// Past two-thirds of its life, where ACME clients renew, and not long expired.
    fn due(&self, now: DateTime<Utc>) -> bool {
        let renew_from = self.not_before + (self.not_after - self.not_before) * 2 / 3;
        now >= renew_from && now - self.not_after <= Duration::days(FORGOTTEN_AFTER_DAYS)
    }

    fn succeeds(&self, earlier: &Leaf) -> bool {
        self.cert.broker_id == earlier.cert.broker_id
            && self.names == earlier.names
            && self.not_before > earlier.not_before
    }
}

/// The unrevoked leaves of the `watched` brokers that are due for renewal and have no later unrevoked
/// leaf for the same names, soonest to expire first.
pub fn leaves_due(watched: &[i64], certs: &[BrokerCert], now: DateTime<Utc>) -> Vec<LeafDue> {
    let leaves: Vec<Leaf> = certs
        .iter()
        .filter(|c| c.revoked_at.is_none() && watched.contains(&c.broker_id))
        .filter_map(Leaf::of)
        .collect();
    let mut due: Vec<LeafDue> = leaves
        .iter()
        .filter(|leaf| leaf.due(now) && !leaves.iter().any(|later| later.succeeds(leaf)))
        .map(|leaf| LeafDue {
            broker_id: leaf.cert.broker_id,
            serial: leaf.cert.serial.clone(),
            name: (leaf.cert.common_name.clone())
                .or_else(|| leaf.cert.sans.first().cloned())
                .unwrap_or_default(),
            days: (leaf.not_after - now).num_days(),
        })
        .collect();
    due.sort_by_key(|leaf| leaf.days);
    due
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::datetime::format_datetime;

    const LIFE: i64 = 90;

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(Utc::now().timestamp(), 0).unwrap()
    }

    fn stamp(at: DateTime<Utc>) -> String {
        format_datetime(at, DateTimeFormat::Openssl)
    }

    /// A 90-day leaf for `names` issued `age` ago.
    fn leaf(serial: &str, names: &[&str], age: Duration, now: DateTime<Utc>) -> BrokerCert {
        let not_before = now - age;
        BrokerCert {
            broker_id: 1,
            serial: serial.into(),
            common_name: Some(names[0].into()),
            sans: names.iter().map(|n| n.to_string()).collect(),
            not_before: stamp(not_before),
            not_after: stamp(not_before + Duration::days(LIFE)),
            issuer_serial: "2".into(),
            revoked_at: None,
            revocation_reason: None,
            changed: 1,
        }
    }

    fn due_serials(certs: &[BrokerCert], now: DateTime<Utc>) -> Vec<String> {
        leaves_due(&[1], certs, now)
            .into_iter()
            .map(|leaf| leaf.serial)
            .collect()
    }

    #[test]
    fn a_leaf_is_due_from_two_thirds_of_its_life() {
        let now = now();
        let at_two_thirds = Duration::days(LIFE * 2 / 3);
        let certs = [
            leaf(
                "1",
                &["a.home.arpa"],
                at_two_thirds - Duration::seconds(1),
                now,
            ),
            leaf("2", &["b.home.arpa"], at_two_thirds, now),
        ];

        assert_eq!(
            leaves_due(&[1], &certs, now),
            [LeafDue {
                broker_id: 1,
                serial: "2".into(),
                name: "b.home.arpa".into(),
                days: 30,
            }]
        );
    }

    #[test]
    fn an_expired_leaf_is_due_for_14_days_then_dropped() {
        let now = now();
        let expired = |serial, days| leaf(serial, &[serial], Duration::days(LIFE + days), now);
        let certs = [expired("13", 13), expired("15", 15)];

        let due = leaves_due(&[1], &certs, now);

        assert_eq!(due.len(), 1);
        assert_eq!((due[0].serial.as_str(), due[0].days), ("13", -13));
    }

    #[test]
    fn a_later_unrevoked_leaf_for_the_same_names_is_its_successor() {
        let now = now();
        let old = Duration::days(70);
        let names = ["a.home.arpa", "b.home.arpa"];
        let renewed = leaf("2", &["B.home.arpa", "a.home.arpa"], Duration::days(1), now);
        let revoked = BrokerCert {
            revoked_at: Some(stamp(now)),
            ..leaf("3", &names, Duration::days(1), now)
        };
        let fewer_names = leaf("4", &names[..1], Duration::days(1), now);
        let other_broker = BrokerCert {
            broker_id: 2,
            ..leaf("5", &names, Duration::days(1), now)
        };

        assert!(due_serials(&[leaf("1", &names, old, now), renewed], now).is_empty());
        for not_a_successor in [revoked, fewer_names, other_broker] {
            let certs = [leaf("1", &names, old, now), not_a_successor];
            assert_eq!(due_serials(&certs, now), ["1"]);
        }
    }

    #[test]
    fn a_revoked_leaf_or_one_of_an_unwatched_broker_is_not_due() {
        let now = now();
        let revoked = BrokerCert {
            revoked_at: Some(stamp(now)),
            ..leaf("1", &["a.home.arpa"], Duration::days(80), now)
        };
        let elsewhere = BrokerCert {
            broker_id: 9,
            ..leaf("2", &["b.home.arpa"], Duration::days(80), now)
        };

        assert!(due_serials(&[revoked, elsewhere], now).is_empty());
    }
}
