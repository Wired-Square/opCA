//! Advisory lock backed by a 1Password Secure Note.
//!
//! Uses `op item create` as an atomic compare-and-swap: if two users
//! race to create the same `CA_Lock` item, only one succeeds.
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
///
/// The lock item is created atomically via `op item create`. If a
/// conflicting item already exists, the lock inspects it for staleness
/// and breaks it if the TTL has been exceeded.
pub struct VaultLock {
    lock_title: String,
    held: bool,
}

impl VaultLock {
    /// Create a new `VaultLock`.
    ///
    /// If `lock_title` is `None`, defaults to `DEFAULT_OP_CONF.lock_title`.
    pub fn new(lock_title: Option<&str>) -> Self {
        Self {
            lock_title: lock_title
                .unwrap_or(DEFAULT_OP_CONF.lock_title)
                .to_string(),
            held: false,
        }
    }

    /// Attempt to acquire the vault lock.
    ///
    /// # Errors
    ///
    /// Returns [`OpcaError::VaultLocked`] if another user holds a
    /// non-stale lock.
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
        let create = || vault.create_item(&self.lock_title, DEFAULT_OP_CONF.category, &assignments);

        match create() {
            Ok(_) => {
                self.held = true;
                return Ok(());
            }
            Err(Error::ItemConflict(_)) => {}
            Err(e) => return Err(e.into()),
        }

        let mut lock_info = read_lock(vault, &self.lock_title)?;

        if is_stale(&lock_info) {
            delete_lock(vault, &self.lock_title)?;

            // Retry once after breaking a stale lock.
            match create() {
                Ok(_) => {
                    self.held = true;
                    return Ok(());
                }
                Err(Error::ItemConflict(_)) => {
                    lock_info = read_lock(vault, &self.lock_title)?;
                }
                Err(e) => return Err(e.into()),
            }
        }

        let field = |label: &str| lock_info.get(label).cloned().unwrap_or_default();
        Err(OpcaError::VaultLocked {
            holder_email: field(FIELD_HOLDER_EMAIL),
            holder_name: field(FIELD_HOLDER_NAME),
            acquired_at: field(FIELD_ACQUIRED_AT),
            operation: field(FIELD_OPERATION),
            hostname: field(FIELD_HOSTNAME),
        })
    }

    /// Release the vault lock (permanent delete so the title is reusable).
    ///
    /// This is idempotent — calling release when the lock is not held
    /// is a no-op.
    pub fn release<R: Runner>(&mut self, vault: &Vault<R>) -> Result<(), OpcaError> {
        if self.held {
            delete_lock(vault, &self.lock_title)?;
            self.held = false;
        }
        Ok(())
    }

    /// Whether the lock is currently held by this instance.
    pub fn held(&self) -> bool {
        self.held
    }

    /// The default TTL in seconds.
    pub const fn default_ttl() -> u64 {
        DEFAULT_TTL
    }
}

/// Return `(email, name)` of the currently authenticated user.
fn current_user<R: Runner>(vault: &Vault<R>) -> (String, String) {
    let known = |s: String| if s.is_empty() { "unknown".to_string() } else { s };
    match vault.op().current_user() {
        Ok(user) => (known(user.email), known(user.name)),
        Err(_) => ("unknown".to_string(), "unknown".to_string()),
    }
}

/// The lock's fields by label; empty once another user has deleted it.
fn read_lock<R: Runner>(
    vault: &Vault<R>,
    lock_title: &str,
) -> Result<HashMap<String, String>, OpcaError> {
    match vault.item(&ItemRef::title(lock_title)) {
        Ok(item) => Ok(item
            .fields
            .into_iter()
            .filter(|f| !f.label.is_empty())
            .map(|f| (f.label, f.value.map(|v| v.expose().to_string()).unwrap_or_default()))
            .collect()),
        Err(Error::ItemNotFound(_)) => Ok(HashMap::new()),
        Err(e) => Err(e.into()),
    }
}

fn delete_lock<R: Runner>(vault: &Vault<R>, lock_title: &str) -> Result<(), OpcaError> {
    match vault.delete_item_permanently(&ItemRef::title(lock_title)) {
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
    use crate::testutil::{created, fake_vault, not_found, FakeRunner, Output};

    const ALICE: &str = r#"{"id":"U1","email":"alice@example.com","name":"Alice"}"#;
    const CONFLICT: &str = "[ERROR] item already exists";

    fn lock_item(email: &str, acquired_at: &str) -> Output {
        Output::ok(crate::testutil::item_json(
            "CA_Lock",
            &[
                (FIELD_HOLDER_EMAIL, email),
                (FIELD_HOLDER_NAME, "Bob"),
                (FIELD_ACQUIRED_AT, acquired_at),
                (FIELD_OPERATION, "cert_revoke"),
                (FIELD_HOSTNAME, "bobs-mac"),
                (FIELD_TTL, "300"),
            ],
        ))
    }

    fn timestamp(offset_secs: i64) -> String {
        (Utc::now() + chrono::Duration::seconds(offset_secs))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    }

    /// A fake that has answered who the user is and created the lock.
    fn acquired() -> FakeRunner {
        let fake = FakeRunner::new();
        fake.respond(Output::ok(ALICE)).respond(created("CA_Lock"));
        fake
    }

    // -- acquire ----------------------------------------------------------

    #[test]
    fn acquire_succeeds() {
        let fake = acquired();
        let mut lock = VaultLock::new(None);
        lock.acquire(&fake_vault(&fake), "cert_create", 300).unwrap();
        assert!(lock.held());
        assert!(fake.is_done());
    }

    #[test]
    fn the_lock_fields_go_on_stdin_with_their_python_labels() {
        let fake = acquired();
        VaultLock::new(None)
            .acquire(&fake_vault(&fake), "cert_create", 300)
            .unwrap();

        let create = &fake.calls()[1];
        assert_eq!(create.args()[..3], ["item", "create", "-"]);
        assert!(create.args().contains(&"--title=CA_Lock".to_string()));
        let template: serde_json::Value = serde_json::from_slice(create.stdin().unwrap()).unwrap();
        let field = |label: &str| {
            template["fields"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["label"] == label)
                .map(|f| f["value"].as_str().unwrap().to_string())
                .unwrap()
        };
        assert_eq!(field(FIELD_HOLDER_EMAIL), "alice@example.com");
        assert_eq!(field(FIELD_HOLDER_NAME), "Alice");
        assert_eq!(field(FIELD_OPERATION), "cert_create");
        assert_eq!(field(FIELD_TTL), "300");
        assert!(parse_iso(&field(FIELD_ACQUIRED_AT)).is_some());
    }

    #[test]
    fn vault_locked_when_held_by_another() {
        let fake = FakeRunner::new();
        fake.respond(Output::ok(ALICE))
            .respond(Output::fail(CONFLICT))
            .respond(lock_item("bob@example.com", &timestamp(0)));

        let mut lock = VaultLock::new(None);
        let err = lock.acquire(&fake_vault(&fake), "cert_create", 300).unwrap_err();

        assert!(!lock.held());
        match err {
            OpcaError::VaultLocked { holder_email, holder_name, operation, hostname, .. } => {
                assert_eq!(holder_email, "bob@example.com");
                assert_eq!(holder_name, "Bob");
                assert_eq!(operation, "cert_revoke");
                assert_eq!(hostname, "bobs-mac");
            }
            other => panic!("Expected VaultLocked, got: {other:?}"),
        }
    }

    #[test]
    fn breaks_stale_lock_and_reacquires() {
        let fake = FakeRunner::new();
        fake.respond(Output::ok(ALICE))
            .respond(Output::fail(CONFLICT))
            .respond(lock_item("bob@example.com", &timestamp(-600)))
            .respond(Output::ok(""))
            .respond(created("CA_Lock"));

        let mut lock = VaultLock::new(None);
        lock.acquire(&fake_vault(&fake), "cert_create", 300).unwrap();
        assert!(lock.held());
        assert!(fake.is_done());
    }

    #[test]
    fn corrupt_lock_treated_as_stale() {
        let fake = FakeRunner::new();
        fake.respond(Output::ok(ALICE))
            .respond(Output::fail(CONFLICT))
            .respond(lock_item("bob@example.com", "not-a-valid-date"))
            .respond(Output::ok(""))
            .respond(created("CA_Lock"));

        let mut lock = VaultLock::new(None);
        lock.acquire(&fake_vault(&fake), "cert_create", 300).unwrap();
        assert!(lock.held());
    }

    #[test]
    fn acquire_propagates_read_lock_error() {
        let fake = FakeRunner::new();
        fake.respond(Output::ok(ALICE))
            .respond(Output::fail(CONFLICT))
            .respond(Output::fail("You are not currently signed in"));

        let mut lock = VaultLock::new(None);
        let err = lock.acquire(&fake_vault(&fake), "cert_create", 300).unwrap_err();

        assert!(!lock.held());
        assert!(matches!(err, OpcaError::AuthenticationFailed), "{err:?}");
    }

    #[test]
    fn acquire_treats_disappeared_lock_as_stale() {
        let fake = FakeRunner::new();
        fake.respond(Output::ok(ALICE))
            .respond(Output::fail(CONFLICT))
            .respond(not_found("CA_Lock"))
            .respond(not_found("CA_Lock"))
            .respond(created("CA_Lock"));

        let mut lock = VaultLock::new(None);
        lock.acquire(&fake_vault(&fake), "cert_create", 300).unwrap();
        assert!(lock.held());
        assert!(fake.is_done());
    }

    #[test]
    fn custom_lock_title() {
        let fake = acquired();
        VaultLock::new(Some("Custom_Lock"))
            .acquire(&fake_vault(&fake), "test", 300)
            .unwrap();
        assert!(fake.calls()[1].args().contains(&"--title=Custom_Lock".to_string()));
    }

    // -- release ----------------------------------------------------------

    #[test]
    fn release_deletes_without_archive() {
        let fake = acquired();
        fake.respond(Output::ok(""));

        let vault = fake_vault(&fake);
        let mut lock = VaultLock::new(None);
        lock.acquire(&vault, "test", 300).unwrap();
        lock.release(&vault).unwrap();

        assert!(!lock.held());
        assert_eq!(fake.calls()[2].args(), ["item", "delete", "CA_Lock", "--vault=testvault"]);
    }

    #[test]
    fn release_idempotent() {
        let fake = acquired();
        fake.respond(Output::ok(""));

        let vault = fake_vault(&fake);
        let mut lock = VaultLock::new(None);
        lock.acquire(&vault, "test", 300).unwrap();
        lock.release(&vault).unwrap();
        lock.release(&vault).unwrap();

        assert_eq!(fake.calls().len(), 3);
    }

    #[test]
    fn release_ignores_item_not_found() {
        let fake = acquired();
        fake.respond(not_found("CA_Lock"));

        let vault = fake_vault(&fake);
        let mut lock = VaultLock::new(None);
        lock.acquire(&vault, "test", 300).unwrap();
        lock.release(&vault).unwrap();
        assert!(!lock.held());
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
