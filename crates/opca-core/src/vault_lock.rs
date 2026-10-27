//! Advisory lock backed by a 1Password Secure Note.
//!
//! `op item create` never refuses a title in use, so a create is no
//! compare-and-swap. Each acquirer creates its own `CA_Lock`, then lists them
//! all: the one 1Password created first wins (the lowest item id among equals),
//! and a loser deletes its own copy. Every later call names the lock by its id.
//!
//! # Usage
//!
//! ```ignore
//! let mut lock = VaultLock::new(None);
//! lock.acquire(&vault, "cert_create", 300)?;
//! // … mutating operations …
//! lock.release(&vault)?;
//! ```

use std::collections::HashMap;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

use crate::constants::DEFAULT_OP_CONF;
use crate::error::OpcaError;
use crate::op::{Assignment, Error, FieldType, ItemRef, Runner, Vault};

// Field labels written onto the CA_Lock Secure Note.
// These must match the Python implementation exactly.
const FIELD_HOLDER_EMAIL: &str = "holder_email";
const FIELD_HOLDER_NAME: &str = "holder_name";
const FIELD_ACQUIRED_AT: &str = "acquired_at";
const FIELD_OPERATION: &str = "operation";
const FIELD_HOSTNAME: &str = "hostname";
const FIELD_TTL: &str = "ttl_seconds";

/// Default lock TTL in seconds.
const DEFAULT_TTL: u64 = 300;

/// Advisory lock backed by a 1Password Secure Note.
pub struct VaultLock {
    lock_title: String,
    held: Option<Held>,
}

/// The lock item this instance holds, and when it goes stale.
struct Held {
    id: String,
    acquired: Instant,
    ttl: Duration,
}

/// One `CA_Lock` item: its id, when 1Password created it, and its fields by label.
struct Lock {
    id: String,
    created: Option<DateTime<Utc>>,
    fields: HashMap<String, String>,
}

impl Lock {
    /// Earliest first by the server's creation time, or by the holder's
    /// `acquired_at` (an unreadable one before any) when that is not known for
    /// every lock; the lowest id among equals.
    fn rank(&self, by_server: bool) -> (Option<DateTime<Utc>>, &str) {
        let at = if by_server {
            self.created
        } else {
            self.fields
                .get(FIELD_ACQUIRED_AT)
                .and_then(|at| parse_iso(at))
        };
        (at, &self.id)
    }

    fn field(&self, label: &str) -> String {
        self.fields.get(label).cloned().unwrap_or_default()
    }

    fn held_against_us(&self) -> OpcaError {
        OpcaError::VaultLocked {
            holder_email: self.field(FIELD_HOLDER_EMAIL),
            holder_name: self.field(FIELD_HOLDER_NAME),
            acquired_at: self.field(FIELD_ACQUIRED_AT),
            operation: self.field(FIELD_OPERATION),
            hostname: self.field(FIELD_HOSTNAME),
        }
    }
}

impl VaultLock {
    /// Create a new `VaultLock`.
    ///
    /// If `lock_title` is `None`, defaults to `DEFAULT_OP_CONF.lock_title`.
    pub fn new(lock_title: Option<&str>) -> Self {
        Self {
            lock_title: lock_title.unwrap_or(DEFAULT_OP_CONF.lock_title).to_string(),
            held: None,
        }
    }

    /// Attempt to acquire the vault lock.
    ///
    /// # Errors
    ///
    /// Returns [`OpcaError::VaultLocked`] if another holder's lock was
    /// acquired first and is not yet past its TTL.
    pub fn acquire<R: Runner>(
        &mut self,
        vault: &Vault<R>,
        operation: &str,
        ttl: u64,
    ) -> Result<(), OpcaError> {
        let (holder_email, holder_name) = current_user(vault);
        let hostname = gethostname::gethostname().to_string_lossy().into_owned();
        let fields = [
            (FIELD_HOLDER_EMAIL, holder_email),
            (FIELD_HOLDER_NAME, holder_name),
            (FIELD_ACQUIRED_AT, now_utc_iso()),
            (FIELD_OPERATION, operation.to_string()),
            (FIELD_HOSTNAME, hostname),
            (FIELD_TTL, ttl.to_string()),
        ];
        let assignments: Vec<Assignment> = fields
            .iter()
            .map(|(label, value)| Assignment::set(*label, FieldType::Text, value.as_str()))
            .collect();

        let created =
            vault.create_item(&self.lock_title, DEFAULT_OP_CONF.category, &assignments)?;
        let mine = Lock {
            created: parse_rfc3339(&created.created_at),
            id: created.id,
            fields: fields
                .into_iter()
                .map(|(label, value)| (label.to_string(), value))
                .collect(),
        };
        match self.contest(vault, &mine) {
            Ok(()) => {
                self.held = Some(Held {
                    id: mine.id,
                    acquired: Instant::now(),
                    ttl: Duration::from_secs(ttl),
                });
                Ok(())
            }
            Err(e) => {
                let _ = delete_lock(vault, &mine.id);
                Err(e)
            }
        }
    }

    /// Whether `mine` ranks first among the vault's locks, breaking any stale
    /// one that ranks ahead of it.
    fn contest<R: Runner>(&self, vault: &Vault<R>, mine: &Lock) -> Result<(), OpcaError> {
        let mut rivals = Vec::new();
        for item in vault.items_titled(&self.lock_title)? {
            if item.id != mine.id {
                rivals.extend(read_lock(vault, &item.id)?);
            }
        }
        let by_server = mine.created.is_some() && rivals.iter().all(|r| r.created.is_some());
        rivals.sort_by(|a, b| a.rank(by_server).cmp(&b.rank(by_server)));
        let ahead = |rival: &&Lock| rival.rank(by_server) < mine.rank(by_server);
        for rival in rivals.iter().take_while(ahead) {
            if !is_stale(&rival.fields) {
                return Err(rival.held_against_us());
            }
            delete_lock(vault, &rival.id)?;
        }
        Ok(())
    }

    /// Release the vault lock (permanent delete, by id).
    ///
    /// This is idempotent — calling release when the lock is not held
    /// is a no-op.
    pub fn release<R: Runner>(&mut self, vault: &Vault<R>) -> Result<(), OpcaError> {
        if let Some(held) = &self.held {
            delete_lock(vault, &held.id)?;
            self.held = None;
        }
        Ok(())
    }

    /// Whether the lock is currently held by this instance.
    pub fn held(&self) -> bool {
        self.held.is_some()
    }

    /// Whether the lock is held by this instance and not yet past its TTL.
    pub fn held_within_ttl(&self) -> bool {
        self.held
            .as_ref()
            .is_some_and(|held| held.acquired.elapsed() < held.ttl)
    }

    /// The default TTL in seconds.
    pub const fn default_ttl() -> u64 {
        DEFAULT_TTL
    }
}

/// Return `(email, name)` of the currently authenticated user.
fn current_user<R: Runner>(vault: &Vault<R>) -> (String, String) {
    let known = |s: String| {
        if s.is_empty() {
            "unknown".to_string()
        } else {
            s
        }
    };
    match vault.op().current_user() {
        Ok(user) => (known(user.email), known(user.name)),
        Err(_) => ("unknown".to_string(), "unknown".to_string()),
    }
}

/// The lock item `id`, or `None` once another holder has deleted it.
fn read_lock<R: Runner>(vault: &Vault<R>, id: &str) -> Result<Option<Lock>, OpcaError> {
    match vault.item(&ItemRef::id(id)) {
        Ok(item) => Ok(Some(Lock {
            created: parse_rfc3339(&item.created_at),
            id: item.id,
            fields: item
                .fields
                .into_iter()
                .filter(|f| !f.label.is_empty())
                .map(|f| {
                    (
                        f.label,
                        f.value.map(|v| v.expose().to_string()).unwrap_or_default(),
                    )
                })
                .collect(),
        })),
        Err(Error::ItemNotFound(_)) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn delete_lock<R: Runner>(vault: &Vault<R>, id: &str) -> Result<(), OpcaError> {
    match vault.delete_item_permanently(&ItemRef::id(id)) {
        Ok(()) | Err(Error::ItemNotFound(_)) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Check whether a lock has exceeded its TTL.
fn is_stale(lock_info: &HashMap<String, String>) -> bool {
    let acquired_str = match lock_info.get(FIELD_ACQUIRED_AT) {
        Some(s) if !s.is_empty() => s,
        _ => return true, // Missing or empty — treat as stale.
    };

    let default_ttl_str = DEFAULT_TTL.to_string();
    let ttl_str = lock_info
        .get(FIELD_TTL)
        .map(|s| s.as_str())
        .unwrap_or(&default_ttl_str);

    let acquired = match parse_iso(acquired_str) {
        Some(dt) => dt,
        None => return true, // Unparseable — treat as stale.
    };

    let ttl: u64 = match ttl_str.parse() {
        Ok(v) => v,
        Err(_) => return true, // Unparseable TTL — treat as stale.
    };

    let elapsed = Utc::now().signed_duration_since(acquired).num_seconds();
    elapsed > ttl as i64
}

/// Return the current UTC time as an ISO 8601 string.
fn now_utc_iso() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn parse_rfc3339(at: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(at)
        .ok()
        .map(|at| at.with_timezone(&Utc))
}

/// Parse an ISO 8601 UTC timestamp (with or without trailing Z).
fn parse_iso(ts: &str) -> Option<DateTime<Utc>> {
    let ts = ts.trim_end_matches('Z');
    chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S")
        .ok()
        .map(|naive| naive.and_utc())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{FakeRunner, Output, fake_vault, item_id, summary_json};

    const ALICE: &str = r#"{"id":"U1","email":"alice@example.com","name":"Alice"}"#;

    /// `op item get` for a lock, with the server's full-precision `created_at`.
    fn lock_item(id: &str, created_at: &str, email: &str, acquired_at: &str) -> Output {
        Output::ok(
            serde_json::json!({
                "id": id,
                "created_at": created_at,
                "title": "CA_Lock",
                "vault": {"id": crate::testutil::VAULT_ID},
                "fields": [
                    {"label": FIELD_HOLDER_EMAIL, "value": email},
                    {"label": FIELD_HOLDER_NAME, "value": "Bob"},
                    {"label": FIELD_ACQUIRED_AT, "value": acquired_at},
                    {"label": FIELD_OPERATION, "value": "cert_revoke"},
                    {"label": FIELD_HOSTNAME, "value": "bobs-mac"},
                    {"label": FIELD_TTL, "value": "300"},
                ]
            })
            .to_string(),
        )
    }

    /// A server creation time within one second, `micros` into it.
    fn server_at(micros: u32) -> String {
        format!("2026-10-23T12:00:00.{micros:06}+11:00")
    }

    fn summary(id: &str, created_at: &str) -> serde_json::Value {
        let mut item: serde_json::Value =
            serde_json::from_str(&summary_json(id, "CA_Lock")).unwrap();
        item["created_at"] = created_at.into();
        item
    }

    /// `op item list` answering these locks, its `created_at` rounded to the second.
    fn listed(ids: &[&str]) -> Output {
        let items: Vec<_> = ids
            .iter()
            .map(|id| summary(id, "2026-10-23T01:00:00Z"))
            .collect();
        Output::ok(serde_json::to_string(&items).unwrap())
    }

    fn timestamp(offset_secs: i64) -> String {
        (Utc::now() + chrono::Duration::seconds(offset_secs))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    }

    /// A fake answering who the user is and creating the lock `mine` at `created_at`.
    fn creating(mine: &str, created_at: &str) -> FakeRunner {
        let fake = FakeRunner::new();
        fake.respond(Output::ok(ALICE))
            .respond(Output::ok(summary(mine, created_at).to_string()));
        fake
    }

    /// A fake that has created the lone lock `item_id(1)`.
    fn alone() -> (FakeRunner, String) {
        let a = item_id(1);
        let fake = creating(&a, &server_at(1));
        fake.respond(listed(&[&a]));
        (fake, a)
    }

    fn args(fake: &FakeRunner, call: usize) -> Vec<String> {
        fake.calls()[call].args().to_vec()
    }

    fn deleted(fake: &FakeRunner) -> Vec<String> {
        fake.calls()
            .iter()
            .filter(|c| c.args()[..2] == ["item", "delete"])
            .map(|c| c.args()[2].clone())
            .collect()
    }

    fn holder(err: OpcaError) -> String {
        match err {
            OpcaError::VaultLocked { holder_email, .. } => holder_email,
            other => panic!("Expected VaultLocked, got: {other:?}"),
        }
    }

    // -- acquire ----------------------------------------------------------

    #[test]
    fn a_lone_acquire_creates_lists_and_holds() {
        let (fake, _) = alone();

        let mut lock = VaultLock::new(None);
        lock.acquire(&fake_vault(&fake), "cert_create", 300)
            .unwrap();

        assert!(lock.held());
        assert_eq!(fake.calls().len(), 3);
        assert_eq!(args(&fake, 0)[..3], ["user", "get", "--me"]);
        assert_eq!(args(&fake, 2)[..2], ["item", "list"]);
        assert!(fake.is_done());
    }

    #[test]
    fn the_lock_fields_go_on_stdin_with_their_python_labels() {
        let (fake, _) = alone();

        VaultLock::new(None)
            .acquire(&fake_vault(&fake), "cert_create", 300)
            .unwrap();

        let create = &fake.calls()[1];
        assert_eq!(create.args()[..3], ["item", "create", "-"]);
        assert!(create.args().contains(&"--title=CA_Lock".to_string()));
        assert!(
            create
                .args()
                .contains(&"--category=Secure Note".to_string())
        );
        let template: serde_json::Value = serde_json::from_slice(create.stdin().unwrap()).unwrap();
        let field = |label: &str| {
            template["fields"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["label"] == label)
                .cloned()
                .unwrap()
        };
        assert_eq!(field(FIELD_HOLDER_EMAIL)["value"], "alice@example.com");
        assert_eq!(field(FIELD_HOLDER_NAME)["value"], "Alice");
        assert_eq!(field(FIELD_OPERATION)["value"], "cert_create");
        assert_eq!(field(FIELD_TTL)["value"], "300");
        assert_eq!(field(FIELD_ACQUIRED_AT)["type"], "STRING");
        assert!(parse_iso(field(FIELD_ACQUIRED_AT)["value"].as_str().unwrap()).is_some());
        assert!(!create.to_string().contains("alice@example.com"));
    }

    #[test]
    fn losing_a_race_deletes_our_copy_and_names_the_winner() {
        let (winner, mine) = (item_id(1), item_id(2));
        let fake = creating(&mine, &server_at(2));
        fake.respond(listed(&[&mine, &winner]))
            .respond(lock_item(
                &winner,
                &server_at(1),
                "bob@example.com",
                &timestamp(0),
            ))
            .respond(Output::ok(""));

        let mut lock = VaultLock::new(None);
        let err = lock
            .acquire(&fake_vault(&fake), "cert_create", 300)
            .unwrap_err();

        assert!(!lock.held());
        match err {
            OpcaError::VaultLocked {
                holder_email,
                holder_name,
                operation,
                hostname,
                ..
            } => {
                assert_eq!(holder_email, "bob@example.com");
                assert_eq!(holder_name, "Bob");
                assert_eq!(operation, "cert_revoke");
                assert_eq!(hostname, "bobs-mac");
            }
            other => panic!("Expected VaultLocked, got: {other:?}"),
        }
        assert_eq!(args(&fake, 3)[2], winner);
        assert_eq!(deleted(&fake), [mine]);
        assert!(fake.is_done());
    }

    #[test]
    fn an_earlier_create_wins_whatever_its_id() {
        let (mine, earlier) = (item_id(1), item_id(2));
        let fake = creating(&mine, &server_at(2));
        fake.respond(listed(&[&mine, &earlier]))
            .respond(lock_item(
                &earlier,
                &server_at(1),
                "bob@example.com",
                &timestamp(0),
            ))
            .respond(Output::ok(""));

        let mut lock = VaultLock::new(None);
        let err = lock
            .acquire(&fake_vault(&fake), "cert_create", 300)
            .unwrap_err();
        assert_eq!(holder(err), "bob@example.com");
        assert_eq!(deleted(&fake), [mine]);
    }

    #[test]
    fn a_later_create_in_the_same_second_wins_nothing_whatever_its_id() {
        let (mine, first) = (item_id(1), item_id(2));
        let fake = creating(&mine, &server_at(900_000));
        fake.respond(listed(&[&first, &mine]))
            .respond(lock_item(
                &first,
                &server_at(100),
                "bob@example.com",
                &now_utc_iso(),
            ))
            .respond(Output::ok(""));

        let mut lock = VaultLock::new(None);
        let err = lock
            .acquire(&fake_vault(&fake), "cert_create", 300)
            .unwrap_err();

        assert_eq!(holder(err), "bob@example.com");
        assert_eq!(deleted(&fake), [mine]);
    }

    #[test]
    fn winning_a_race_keeps_our_copy_and_leaves_theirs() {
        let (later, mine) = (item_id(1), item_id(2));
        let fake = creating(&mine, &server_at(1));
        fake.respond(listed(&[&later, &mine])).respond(lock_item(
            &later,
            &server_at(2),
            "bob@example.com",
            &timestamp(0),
        ));

        let mut lock = VaultLock::new(None);
        lock.acquire(&fake_vault(&fake), "cert_create", 300)
            .unwrap();

        assert!(lock.held());
        assert!(deleted(&fake).is_empty());
        assert!(fake.is_done());
    }

    #[test]
    fn without_a_server_time_the_earlier_acquired_at_wins() {
        let (mine, rival) = (item_id(1), item_id(2));
        let fake = creating(&mine, &server_at(1));
        fake.respond(listed(&[&mine, &rival]))
            .respond(lock_item(&rival, "", "bob@example.com", &timestamp(-60)))
            .respond(Output::ok(""));

        let mut lock = VaultLock::new(None);
        let err = lock
            .acquire(&fake_vault(&fake), "cert_create", 300)
            .unwrap_err();
        assert_eq!(holder(err), "bob@example.com");
    }

    #[test]
    fn ranking_falls_back_to_acquired_at_then_the_lowest_id() {
        let lock = |id: u32, created: Option<&str>| Lock {
            id: item_id(id),
            created: created.and_then(parse_rfc3339),
            fields: HashMap::from([(
                FIELD_ACQUIRED_AT.to_string(),
                "2026-10-23T10:00:00Z".to_string(),
            )]),
        };
        let first = server_at(1);
        let second = server_at(2);
        assert!(lock(2, Some(&first)).rank(true) < lock(1, Some(&second)).rank(true));
        assert!(lock(1, None).rank(false) < lock(2, None).rank(false));
        let unreadable = Lock {
            id: item_id(9),
            created: None,
            fields: HashMap::new(),
        };
        assert!(unreadable.rank(false) < lock(1, None).rank(false));
    }

    #[test]
    fn a_stale_lock_among_duplicates_is_broken_by_id() {
        let (stale, mine, later) = (item_id(1), item_id(2), item_id(3));
        let fake = creating(&mine, &server_at(2));
        fake.respond(listed(&[&stale, &mine, &later]))
            .respond(lock_item(
                &stale,
                &server_at(1),
                "bob@example.com",
                &timestamp(-600),
            ))
            .respond(lock_item(
                &later,
                &server_at(3),
                "carol@example.com",
                &timestamp(0),
            ))
            .respond(Output::ok(""));

        let mut lock = VaultLock::new(None);
        lock.acquire(&fake_vault(&fake), "cert_create", 300)
            .unwrap();

        assert!(lock.held());
        assert_eq!(deleted(&fake), [stale]);
        assert!(
            fake.calls()
                .iter()
                .all(|c| !c.args().contains(&"CA_Lock".to_string()))
        );
        assert!(fake.is_done());
    }

    #[test]
    fn a_fresh_lock_behind_a_stale_one_still_wins() {
        let (stale, earlier, mine) = (item_id(1), item_id(2), item_id(3));
        let fake = creating(&mine, &server_at(3));
        fake.respond(listed(&[&stale, &earlier, &mine]))
            .respond(lock_item(
                &stale,
                &server_at(1),
                "bob@example.com",
                &timestamp(-600),
            ))
            .respond(lock_item(
                &earlier,
                &server_at(2),
                "carol@example.com",
                &timestamp(-5),
            ))
            .respond(Output::ok(""))
            .respond(Output::ok(""));

        let mut lock = VaultLock::new(None);
        let err = lock
            .acquire(&fake_vault(&fake), "cert_create", 300)
            .unwrap_err();

        assert_eq!(holder(err), "carol@example.com");
        assert_eq!(deleted(&fake), [stale, mine]);
    }

    #[test]
    fn a_corrupt_lock_is_treated_as_stale() {
        let (corrupt, mine) = (item_id(1), item_id(2));
        let fake = creating(&mine, &server_at(2));
        fake.respond(listed(&[&corrupt, &mine]))
            .respond(lock_item(
                &corrupt,
                &server_at(1),
                "bob@example.com",
                "not-a-valid-date",
            ))
            .respond(Output::ok(""));

        let mut lock = VaultLock::new(None);
        lock.acquire(&fake_vault(&fake), "cert_create", 300)
            .unwrap();
        assert_eq!(deleted(&fake), [corrupt]);
    }

    #[test]
    fn a_rival_deleted_before_we_read_it_is_ignored() {
        let (gone, mine) = (item_id(1), item_id(2));
        let fake = creating(&mine, &server_at(2));
        fake.respond(listed(&[&gone, &mine])).respond(Output::fail(
            "[ERROR] \"00000000000000000000000001\" isn't an item in the \"TestVault\" vault.",
        ));

        let mut lock = VaultLock::new(None);
        lock.acquire(&fake_vault(&fake), "cert_create", 300)
            .unwrap();
        assert!(lock.held());
        assert!(deleted(&fake).is_empty());
    }

    #[test]
    fn a_failure_after_the_create_deletes_our_copy() {
        let (rival, mine) = (item_id(1), item_id(2));
        let fake = creating(&mine, &server_at(2));
        fake.respond(listed(&[&rival, &mine]))
            .respond(Output::fail("You are not currently signed in"))
            .respond(Output::ok(""));

        let mut lock = VaultLock::new(None);
        let err = lock
            .acquire(&fake_vault(&fake), "cert_create", 300)
            .unwrap_err();

        assert!(!lock.held());
        assert!(matches!(err, OpcaError::AuthenticationFailed), "{err:?}");
        assert_eq!(deleted(&fake), [mine]);
    }

    #[test]
    fn duplicates_read_by_title_are_ambiguous_with_their_ids() {
        let fake = FakeRunner::new();
        fake.respond(Output::fail(
            "[ERROR] 2026/10/23 10:00:00 More than one item matches \"CA_Lock\". Try again and specify the item by its ID:\n\
             \t* for the item \"CA_Lock\" in vault TestVault: 4ld6tdxnvj5kgsbjbb4e3opyua\n\
             \t* for the item \"CA_Lock\" in vault TestVault: ubvcz6g3xb4bkmrkbs2xq6cfzi\n",
        ));
        let err: OpcaError = fake_vault(&fake)
            .item(&ItemRef::title("CA_Lock"))
            .unwrap_err()
            .into();
        match err {
            OpcaError::AmbiguousItem { title, ids } => {
                assert_eq!(title, "CA_Lock");
                assert_eq!(
                    ids,
                    ["4ld6tdxnvj5kgsbjbb4e3opyua", "ubvcz6g3xb4bkmrkbs2xq6cfzi"]
                );
            }
            other => panic!("Expected AmbiguousItem, got: {other:?}"),
        }
    }

    #[test]
    fn custom_lock_title() {
        let a = item_id(1);
        let fake = creating(&a, &server_at(1));
        fake.respond(Output::ok("[]"));

        VaultLock::new(Some("Custom_Lock"))
            .acquire(&fake_vault(&fake), "test", 300)
            .unwrap();

        assert!(args(&fake, 1).contains(&"--title=Custom_Lock".to_string()));
    }

    // -- release ----------------------------------------------------------

    #[test]
    fn release_deletes_our_lock_by_id_without_archive() {
        let (fake, a) = alone();
        fake.respond(Output::ok(""));

        let vault = fake_vault(&fake);
        let mut lock = VaultLock::new(None);
        lock.acquire(&vault, "test", 300).unwrap();
        lock.release(&vault).unwrap();

        assert!(!lock.held());
        assert_eq!(args(&fake, 3), ["item", "delete", &a, "--vault=testvault"]);
    }

    #[test]
    fn release_idempotent() {
        let (fake, _) = alone();
        fake.respond(Output::ok(""));

        let vault = fake_vault(&fake);
        let mut lock = VaultLock::new(None);
        lock.acquire(&vault, "test", 300).unwrap();
        lock.release(&vault).unwrap();
        lock.release(&vault).unwrap();

        assert_eq!(fake.calls().len(), 4);
    }

    #[test]
    fn release_when_the_lock_is_already_gone() {
        let (fake, _) = alone();
        fake.respond(Output::fail(
            "[ERROR] \"00000000000000000000000001\" isn't an item in the \"TestVault\" vault.",
        ));

        let vault = fake_vault(&fake);
        let mut lock = VaultLock::new(None);
        lock.acquire(&vault, "test", 300).unwrap();
        lock.release(&vault).unwrap();
        assert!(!lock.held());
    }

    #[test]
    fn a_failed_release_keeps_the_lock_held() {
        let (fake, _) = alone();
        fake.respond(Output::fail("[ERROR] boom"));

        let vault = fake_vault(&fake);
        let mut lock = VaultLock::new(None);
        lock.acquire(&vault, "test", 300).unwrap();
        assert!(lock.release(&vault).is_err());
        assert!(lock.held());
    }

    // -- is_stale ---------------------------------------------------------

    fn info(acquired_at: &str) -> HashMap<String, String> {
        HashMap::from([
            (FIELD_ACQUIRED_AT.to_string(), acquired_at.to_string()),
            (FIELD_TTL.to_string(), "300".to_string()),
        ])
    }

    #[test]
    fn fresh_lock_not_stale() {
        assert!(!is_stale(&info(&timestamp(0))));
    }

    #[test]
    fn expired_lock_is_stale() {
        assert!(is_stale(&info(&timestamp(-600))));
    }

    #[test]
    fn missing_acquired_at_is_stale() {
        assert!(is_stale(&HashMap::new()));
    }

    #[test]
    fn unparseable_timestamp_is_stale() {
        assert!(is_stale(&info("garbage")));
    }

    // -- parse_iso --------------------------------------------------------

    #[test]
    fn parse_iso_with_trailing_z() {
        let dt = parse_iso("2025-06-15T10:30:00Z").unwrap();
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2025-06-15");
    }

    #[test]
    fn parse_iso_without_z() {
        let dt = parse_iso("2025-06-15T10:30:00").unwrap();
        assert_eq!(dt.format("%H:%M:%S").to_string(), "10:30:00");
    }

    #[test]
    fn parse_iso_invalid() {
        assert!(parse_iso("not-a-date").is_none());
    }
}
