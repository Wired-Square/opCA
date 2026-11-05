#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use opca_acme_api::Challenge as ChallengeType;
use opca_acme_broker::acme::store::{
    AccountStatus, AuthorisationStatus, ChallengeStatus, Error, Expired, NewAuthorisation,
    NewCertificate, NewOrder, Order, OrderStatus,
};
use opca_acme_broker::acme::{Problem, ProblemType, Store};
use tempfile::TempDir;
use wslib_db_sqlite::sqlx::{self, Row};

const HOUR: Duration = Duration::from_secs(3600);

async fn open() -> (TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = reopen(&dir).await;
    (dir, store)
}

async fn reopen(dir: &TempDir) -> Store {
    let provider = Arc::new(rustls_openssl::default_provider());
    Store::open(&dir.path().join("acme.db"), provider)
        .await
        .unwrap()
}

async fn account(store: &Store, thumbprint: &str) -> i64 {
    store
        .create_account(r#"{"kty":"EC"}"#, thumbprint, &[])
        .await
        .unwrap()
        .0
        .id
}

fn authorisation(name: &str, expires: SystemTime) -> NewAuthorisation {
    let (identifier, wildcard) = match name.strip_prefix("*.") {
        Some(base) => (base, true),
        None => (name, false),
    };
    NewAuthorisation {
        identifier: identifier.into(),
        wildcard,
        expires,
        challenges: if wildcard {
            vec![ChallengeType::Dns01]
        } else {
            vec![ChallengeType::Http01, ChallengeType::TlsAlpn01]
        },
    }
}

fn new_order(account: i64, names: &[&str], expires: SystemTime) -> NewOrder {
    NewOrder {
        account,
        identifiers: names.iter().map(|name| name.to_string()).collect(),
        not_before: None,
        not_after: None,
        expires,
        authorisations: names
            .iter()
            .map(|name| authorisation(name, expires))
            .collect(),
    }
}

/// Validates the first challenge of each of the order's authorisations.
async fn validate_all(store: &Store, order: &Order) {
    for &id in &order.authorisations {
        let challenge = store.authorisation(id).await.unwrap().unwrap().challenges[0].id;
        store
            .set_challenge_status(challenge, ChallengeStatus::Processing, None)
            .await
            .unwrap();
        store
            .set_challenge_status(challenge, ChallengeStatus::Valid, None)
            .await
            .unwrap();
    }
}

async fn ready_order(store: &Store, account: i64, name: &str) -> Order {
    let order = store
        .create_order(&new_order(account, &[name], SystemTime::now() + HOUR))
        .await
        .unwrap();
    validate_all(store, &order).await;
    order
}

fn issued(serial: &str, name: &str) -> NewCertificate {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    NewCertificate {
        serial: serial.into(),
        common_name: Some(name.into()),
        sans: vec![name.into()],
        not_before: now,
        not_after: now + 30 * 24 * HOUR,
        chain_pem: "-----BEGIN CERTIFICATE-----\n…".into(),
    }
}

#[tokio::test]
async fn opening_makes_every_table_owner_only_and_reopening_migrates_nothing_twice() {
    let (dir, store) = open().await;
    account(&store, "kept").await;
    drop(store);

    let path = dir.path().join("acme.db");
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let store = reopen(&dir).await;
    assert!(store.account_by_thumbprint("kept").await.unwrap().is_some());

    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", path.display()))
        .await
        .unwrap();
    let tables: Vec<String> = sqlx::query(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '\\_%' ESCAPE '\\' \
         AND name <> 'sqlite_sequence' ORDER BY name",
    )
    .fetch_all(&pool)
    .await
    .unwrap()
    .iter()
    .map(|row| row.get(0))
    .collect();
    assert_eq!(
        tables,
        [
            "accounts",
            "authorisations",
            "certificates",
            "challenges",
            "eab_keys",
            "orders"
        ]
    );
    let applied: Vec<i64> = sqlx::query_scalar("SELECT version FROM _acme_migrations")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(applied, [1]);
    let eab: i64 = sqlx::query_scalar("SELECT count(*) FROM eab_keys")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(eab, 0);
}

#[tokio::test]
async fn an_account_is_made_once_per_thumbprint() {
    let (_dir, store) = open().await;
    let contacts = ["mailto:ops@home.example".to_string()];
    let (made, new) = store
        .create_account(r#"{"crv":"P-256"}"#, "thumb", &contacts)
        .await
        .unwrap();
    assert!(new);
    assert_eq!(made.status, AccountStatus::Valid);
    assert_eq!(made.contacts, contacts);

    let (again, new) = store
        .create_account(r#"{"other":1}"#, "thumb", &[])
        .await
        .unwrap();
    assert!(!new);
    assert_eq!(again, made);
    assert_eq!(store.account(made.id).await.unwrap(), Some(made.clone()));
    assert_eq!(
        store.account_by_thumbprint("thumb").await.unwrap(),
        Some(made)
    );
    assert_eq!(store.account_by_thumbprint("none").await.unwrap(), None);
}

#[tokio::test]
async fn an_account_once_deactivated_stays_so() {
    let (_dir, store) = open().await;
    let id = account(&store, "thumb").await;
    store
        .set_account_status(id, AccountStatus::Deactivated)
        .await
        .unwrap();
    assert!(matches!(
        store.set_account_status(id, AccountStatus::Valid).await,
        Err(Error::Transition {
            table: "accounts",
            from: "deactivated",
            to: "valid"
        })
    ));
    assert!(matches!(
        store.set_account_status(999, AccountStatus::Revoked).await,
        Err(Error::NotFound {
            table: "accounts",
            ..
        })
    ));
}

#[tokio::test]
async fn an_order_is_made_pending_with_a_token_per_challenge() {
    let (_dir, store) = open().await;
    let id = account(&store, "thumb").await;
    let expires = SystemTime::UNIX_EPOCH + Duration::from_secs(1_900_000_000);
    let order = store
        .create_order(&new_order(
            id,
            &["www.home.example", "*.home.example"],
            expires,
        ))
        .await
        .unwrap();
    assert_eq!(order.status, OrderStatus::Pending);
    assert_eq!(order.identifiers, ["www.home.example", "*.home.example"]);
    assert_eq!(order.expires, expires);
    assert_eq!(order.authorisations.len(), 2);

    let plain = store
        .authorisation(order.authorisations[0])
        .await
        .unwrap()
        .unwrap();
    let wildcard = store
        .authorisation(order.authorisations[1])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (plain.identifier.as_str(), plain.wildcard),
        ("www.home.example", false)
    );
    assert_eq!(
        (wildcard.identifier.as_str(), wildcard.wildcard),
        ("home.example", true)
    );
    let kinds = |a: &opca_acme_broker::acme::store::Authorisation| {
        a.challenges.iter().map(|c| c.kind).collect::<Vec<_>>()
    };
    assert_eq!(
        kinds(&plain),
        [ChallengeType::Http01, ChallengeType::TlsAlpn01]
    );
    assert_eq!(kinds(&wildcard), [ChallengeType::Dns01]);

    let tokens: Vec<&str> = plain
        .challenges
        .iter()
        .chain(&wildcard.challenges)
        .map(|c| c.token.as_str())
        .collect();
    assert!(tokens.iter().all(|t| {
        t.len() == 43
            && t.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }));
    assert_ne!(tokens[0], tokens[1]);
    assert!(
        plain
            .challenges
            .iter()
            .all(|c| c.status == ChallengeStatus::Pending && c.validated.is_none())
    );
}

#[tokio::test]
async fn a_valid_challenge_validates_its_authorisation_and_the_last_one_readies_the_order() {
    let (_dir, store) = open().await;
    let id = account(&store, "thumb").await;
    let order = store
        .create_order(&new_order(
            id,
            &["a.home.example", "b.home.example"],
            SystemTime::now() + HOUR,
        ))
        .await
        .unwrap();
    let first = store
        .authorisation(order.authorisations[0])
        .await
        .unwrap()
        .unwrap();
    let challenge = first.challenges[0].id;
    store
        .set_challenge_status(challenge, ChallengeStatus::Processing, None)
        .await
        .unwrap();
    store
        .set_challenge_status(challenge, ChallengeStatus::Valid, None)
        .await
        .unwrap();

    let validated = store.challenge(challenge).await.unwrap().unwrap();
    assert_eq!(validated.status, ChallengeStatus::Valid);
    assert!(validated.validated.is_some());
    let first = store.authorisation(first.id).await.unwrap().unwrap();
    assert_eq!(first.status, AuthorisationStatus::Valid);
    assert_eq!(first.challenges[1].status, ChallengeStatus::Pending);
    let pending = store.order(order.id).await.unwrap().unwrap();
    assert_eq!(pending.status, OrderStatus::Pending);

    validate_all(
        &store,
        &Order {
            authorisations: vec![order.authorisations[1]],
            ..order.clone()
        },
    )
    .await;
    let ready = store.order(order.id).await.unwrap().unwrap();
    assert_eq!(ready.status, OrderStatus::Ready);
}

#[tokio::test]
async fn an_invalid_challenge_fails_its_authorisation_and_order_with_the_problem() {
    let (_dir, store) = open().await;
    let id = account(&store, "thumb").await;
    let order = store
        .create_order(&new_order(
            id,
            &["a.home.example"],
            SystemTime::now() + HOUR,
        ))
        .await
        .unwrap();
    let challenge = store
        .authorisation(order.authorisations[0])
        .await
        .unwrap()
        .unwrap()
        .challenges[0]
        .id;
    let problem = Problem::new(ProblemType::IncorrectResponse, "wrong body");
    store
        .set_challenge_status(challenge, ChallengeStatus::Processing, None)
        .await
        .unwrap();
    store
        .set_challenge_status(challenge, ChallengeStatus::Invalid, Some(&problem))
        .await
        .unwrap();

    let failed = store.challenge(challenge).await.unwrap().unwrap();
    assert_eq!(
        (failed.status, failed.error),
        (ChallengeStatus::Invalid, Some(problem))
    );
    assert_eq!(failed.validated, None);
    let authorisation = store
        .authorisation(order.authorisations[0])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(authorisation.status, AuthorisationStatus::Invalid);
    let order = store.order(order.id).await.unwrap().unwrap();
    assert_eq!(order.status, OrderStatus::Invalid);
}

#[tokio::test]
async fn a_challenge_may_go_back_from_processing_to_pending() {
    let (_dir, store) = open().await;
    let id = account(&store, "thumb").await;
    let order = store
        .create_order(&new_order(
            id,
            &["a.home.example"],
            SystemTime::now() + HOUR,
        ))
        .await
        .unwrap();
    let authorisation = store
        .authorisation(order.authorisations[0])
        .await
        .unwrap()
        .unwrap();
    let challenge = authorisation.challenges[0].id;
    assert!(matches!(
        store
            .set_challenge_status(challenge, ChallengeStatus::Valid, None)
            .await,
        Err(Error::Transition {
            table: "challenges",
            from: "pending",
            to: "valid"
        })
    ));
    for status in [ChallengeStatus::Processing, ChallengeStatus::Pending] {
        store
            .set_challenge_status(challenge, status, None)
            .await
            .unwrap();
    }
    let authorisation = store
        .authorisation(authorisation.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(authorisation.status, AuthorisationStatus::Pending);
}

#[tokio::test]
async fn a_deactivated_authorisation_fails_its_order() {
    let (_dir, store) = open().await;
    let id = account(&store, "thumb").await;
    let order = store
        .create_order(&new_order(
            id,
            &["a.home.example", "b.home.example"],
            SystemTime::now() + HOUR,
        ))
        .await
        .unwrap();
    store
        .set_authorisation_status(order.authorisations[1], AuthorisationStatus::Deactivated)
        .await
        .unwrap();
    let order = store.order(order.id).await.unwrap().unwrap();
    assert_eq!(order.status, OrderStatus::Invalid);
    assert!(matches!(
        store
            .set_order_status(order.id, OrderStatus::Ready, None)
            .await,
        Err(Error::Transition {
            table: "orders",
            from: "invalid",
            ..
        })
    ));
}

#[tokio::test]
async fn an_order_moves_through_processing_and_keeps_its_error() {
    let (_dir, store) = open().await;
    let id = account(&store, "thumb").await;
    let order = ready_order(&store, id, "a.home.example").await;
    let problem = Problem::new(ProblemType::ServerInternal, "signing failed");
    store
        .set_order_status(order.id, OrderStatus::Processing, None)
        .await
        .unwrap();
    store
        .set_order_status(order.id, OrderStatus::Invalid, Some(&problem))
        .await
        .unwrap();
    let order = store.order(order.id).await.unwrap().unwrap();
    assert_eq!(
        (order.status, order.error),
        (OrderStatus::Invalid, Some(problem))
    );
}

#[tokio::test]
async fn a_certificate_is_recorded_only_for_a_ready_or_processing_order() {
    let (_dir, store) = open().await;
    let id = account(&store, "thumb").await;
    let pending = store
        .create_order(&new_order(
            id,
            &["p.home.example"],
            SystemTime::now() + HOUR,
        ))
        .await
        .unwrap();
    assert!(matches!(
        store
            .record_certificate(pending.id, &issued("1", "p.home.example"))
            .await,
        Err(Error::Transition {
            table: "orders",
            from: "pending",
            ..
        })
    ));

    let order = ready_order(&store, id, "a.home.example").await;
    let recorded = store
        .record_certificate(order.id, &issued("12345", "a.home.example"))
        .await
        .unwrap();
    assert_eq!(
        (recorded.account, recorded.order, recorded.serial.as_str()),
        (id, order.id, "12345")
    );
    assert_eq!(recorded.sans, ["a.home.example"]);
    assert_eq!(recorded.revoked_at, None);
    let order = store.order(order.id).await.unwrap().unwrap();
    assert_eq!(
        (order.status, order.certificate),
        (OrderStatus::Valid, Some(recorded.id))
    );
    assert_eq!(
        store.certificate(recorded.id).await.unwrap(),
        Some(recorded)
    );

    let processing = ready_order(&store, id, "b.home.example").await;
    store
        .set_order_status(processing.id, OrderStatus::Processing, None)
        .await
        .unwrap();
    assert!(matches!(
        store
            .record_certificate(processing.id, &issued("12345", "b.home.example"))
            .await,
        Err(Error::Db(_))
    ));
    let unchanged = store.order(processing.id).await.unwrap().unwrap();
    assert_eq!(unchanged.status, OrderStatus::Processing);
}

#[tokio::test]
async fn a_certificate_is_revoked_once() {
    let (_dir, store) = open().await;
    let id = account(&store, "thumb").await;
    let order = ready_order(&store, id, "a.home.example").await;
    store
        .record_certificate(order.id, &issued("777", "a.home.example"))
        .await
        .unwrap();

    let revoked = store.revoke("777", Some(1)).await.unwrap();
    assert!(revoked.revoked_at.is_some());
    assert_eq!(revoked.revocation_reason, Some(1));
    assert!(matches!(
        store.revoke("777", None).await,
        Err(Error::AlreadyRevoked { .. })
    ));
    assert!(matches!(
        store.revoke("778", None).await,
        Err(Error::NotFound {
            table: "certificates",
            ..
        })
    ));
}

#[tokio::test]
async fn the_cursor_returns_what_was_recorded_after_it_in_order() {
    let (_dir, store) = open().await;
    let id = account(&store, "thumb").await;
    let mut recorded = Vec::new();
    for (serial, name) in [("10", "a"), ("20", "b"), ("30", "c")] {
        let name = format!("{name}.home.example");
        let order = ready_order(&store, id, &name).await;
        recorded.push(
            store
                .record_certificate(order.id, &issued(serial, &name))
                .await
                .unwrap(),
        );
    }
    assert!(recorded.windows(2).all(|pair| pair[0].id < pair[1].id));

    let serials = |certificates: Vec<opca_acme_broker::acme::store::Certificate>| {
        certificates
            .into_iter()
            .map(|c| c.serial)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        serials(store.issued_after(0, 10).await.unwrap()),
        ["10", "20", "30"]
    );
    assert_eq!(
        serials(store.issued_after(recorded[0].id, 10).await.unwrap()),
        ["20", "30"]
    );
    assert_eq!(serials(store.issued_after(0, 1).await.unwrap()), ["10"]);
    assert!(
        store
            .issued_after(recorded[2].id, 10)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn stale_orders_and_authorisations_expire_and_take_their_orders_with_them() {
    let (_dir, store) = open().await;
    let id = account(&store, "thumb").await;
    let now = SystemTime::now();

    let stale = store
        .create_order(&new_order(id, &["stale.home.example"], now - HOUR))
        .await
        .unwrap();
    let mut short = new_order(id, &["short.home.example"], now + HOUR);
    short.authorisations[0].expires = now - HOUR;
    let short = store.create_order(&short).await.unwrap();
    let fresh = store
        .create_order(&new_order(id, &["fresh.home.example"], now + HOUR))
        .await
        .unwrap();
    let done = ready_order(&store, id, "done.home.example").await;
    store
        .record_certificate(done.id, &issued("1", "done.home.example"))
        .await
        .unwrap();

    assert_eq!(
        store.expire_stale(now).await.unwrap(),
        Expired {
            orders: 2,
            authorisations: 2,
        }
    );
    let status = |order: &Order| {
        let store = store.clone();
        let id = order.id;
        async move { store.order(id).await.unwrap().unwrap().status }
    };
    assert_eq!(status(&stale).await, OrderStatus::Invalid);
    assert_eq!(status(&short).await, OrderStatus::Invalid);
    assert_eq!(status(&fresh).await, OrderStatus::Pending);
    assert_eq!(status(&done).await, OrderStatus::Valid);
    let expired = store
        .authorisation(short.authorisations[0])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(expired.status, AuthorisationStatus::Expired);
    assert_eq!(store.expire_stale(now).await.unwrap(), Expired::default());
}
