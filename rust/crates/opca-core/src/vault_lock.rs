//! Advisory lock backed by a 1Password Secure Note.
//!
//! Uses `op item create` as an atomic compare-and-swap: if two users
//! race to create the same `CA_Lock` item, only one succeeds.
//!
//! # Usage
//!
//! ```ignore
//! let mut lock = VaultLock::new(None);
//! lock.acquire(&op, "cert_create", 300)?;
//! // … mutating operations …
//! lock.release(&op)?;
//! ```

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use crate::constants::DEFAULT_OP_CONF;
use crate::error::OpcaError;
use crate::op::{CommandRunner, Op, StoreAction};

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
    /// # Arguments
    ///
    /// * `op` — 1Password CLI wrapper.
    /// * `operation` — Human-readable description of the operation.
    /// * `ttl` — Maximum seconds the lock may be held before it is
    ///   considered stale and eligible for automatic breaking.
    ///
    /// # Errors
    ///
    /// Returns [`OpcaError::VaultLocked`] if another user holds a
    /// non-stale lock.
    pub fn acquire<R: CommandRunner>(
        &mut self,
        op: &Op<R>,
        operation: &str,
        ttl: u64,
    ) -> Result<(), OpcaError> {
        let (holder_email, holder_name) = current_user(op);
        let hostname = gethostname::gethostname()
            .to_string_lossy()
            .into_owned();
        let acquired_at = now_utc_iso();

        let attr_email = format!("{FIELD_HOLDER_EMAIL}[text]={holder_email}");
        let attr_name = format!("{FIELD_HOLDER_NAME}[text]={holder_name}");
        let attr_time = format!("{FIELD_ACQUIRED_AT}[text]={acquired_at}");
        let attr_op = format!("{FIELD_OPERATION}[text]={operation}");
        let attr_host = format!("{FIELD_HOSTNAME}[text]={hostname}");
        let attr_ttl = format!("{FIELD_TTL}[text]={ttl}");

        let attrs: Vec<&str> = vec![
            &attr_email,
            &attr_name,
            &attr_time,
            &attr_op,
            &attr_host,
            &attr_ttl,
        ];

        // First attempt — atomic create.
        match op.store_item(
            &self.lock_title,
            Some(&attrs),
            StoreAction::Create,
            DEFAULT_OP_CONF.category,
            None,
            None,
        ) {
            Ok(_) => {
                self.held = true;
                return Ok(());
            }
            Err(OpcaError::ItemConflict(_)) => {
                // Someone else holds the lock — inspect it.
            }
            Err(e) => return Err(e),
        }

        // Lock exists. Read it to decide whether it is stale.
        let mut lock_info = read_lock(op, &self.lock_title);

        if is_stale(&lock_info) {
            break_stale(op, &self.lock_title)?;

            // Retry once after breaking a stale lock.
            match op.store_item(
                &self.lock_title,
                Some(&attrs),
                StoreAction::Create,
                DEFAULT_OP_CONF.category,
                None,
                None,
            ) {
                Ok(_) => {
                    self.held = true;
                    return Ok(());
                }
                Err(OpcaError::ItemConflict(_)) => {
                    // Another user beat us to re-acquire after the stale break.
                    lock_info = read_lock(op, &self.lock_title);
                }
                Err(e) => return Err(e),
            }
        }

        Err(OpcaError::VaultLocked {
            holder_email: lock_info
                .get(FIELD_HOLDER_EMAIL)
                .cloned()
                .unwrap_or_default(),
            holder_name: lock_info
                .get(FIELD_HOLDER_NAME)
                .cloned()
                .unwrap_or_default(),
            acquired_at: lock_info
                .get(FIELD_ACQUIRED_AT)
                .cloned()
                .unwrap_or_default(),
            operation: lock_info
                .get(FIELD_OPERATION)
                .cloned()
                .unwrap_or_default(),
            hostname: lock_info
                .get(FIELD_HOSTNAME)
                .cloned()
                .unwrap_or_default(),
        })
    }

    /// Release the vault lock (permanent delete so the title is reusable).
    ///
    /// This is idempotent — calling release when the lock is not held
    /// is a no-op.
    pub fn release<R: CommandRunner>(&mut self, op: &Op<R>) -> Result<(), OpcaError> {
        if !self.held {
            return Ok(());
        }
        match op.delete_item(&self.lock_title, false) {
            Ok(_) => {}
            Err(OpcaError::ItemNotFound(_)) => {
                // Lock item already removed.
            }
            Err(e) => return Err(e),
        }
        self.held = false;
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

// ------------------------------------------------------------------
// Private helpers
// ------------------------------------------------------------------

/// Return `(email, name)` of the currently authenticated user.
fn current_user<R: CommandRunner>(op: &Op<R>) -> (String, String) {
    match op.get_current_user_details() {
        Ok(stdout) => {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&stdout) {
                let email = data
                    .get("email")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                let name = data
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                return (email, name);
            }
            ("unknown".to_string(), "unknown".to_string())
        }
        Err(_) => ("unknown".to_string(), "unknown".to_string()),
    }
}

/// Read the existing lock item and return its fields as label→value pairs.
fn read_lock<R: CommandRunner>(op: &Op<R>, lock_title: &str) -> HashMap<String, String> {
    match op.get_item(lock_title, "json") {
        Ok(stdout) => extract_fields(&stdout),
        Err(_) => HashMap::new(),
    }
}

/// Pull label→value pairs from a 1Password item JSON blob.
fn extract_fields(json_str: &str) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    if let Ok(data) = serde_json::from_str::<serde_json::Value>(json_str) {
        if let Some(arr) = data.get("fields").and_then(|v| v.as_array()) {
            for f in arr {
                let label = f
                    .get("label")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let value = f
                    .get("value")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if !label.is_empty() {
                    fields.insert(label.to_string(), value.to_string());
                }
            }
        }
    }
    fields
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

/// Delete a stale lock item so a new one can be created.
fn break_stale<R: CommandRunner>(op: &Op<R>, lock_title: &str) -> Result<(), OpcaError> {
    match op.delete_item(lock_title, false) {
        Ok(_) => Ok(()),
        Err(OpcaError::ItemNotFound(_)) => Ok(()), // Already gone.
        Err(e) => Err(e),
    }
}

/// Return the current UTC time as an ISO 8601 string.
fn now_utc_iso() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Parse an ISO 8601 UTC timestamp (with or without trailing Z).
fn parse_iso(ts: &str) -> Option<DateTime<Utc>> {
    let ts = ts.trim_end_matches('Z');
    // Try parsing with chrono's flexible parser.
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S") {
        return Some(naive.and_utc());
    }
    None
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{err_output, mock_op, ok_output};

    /// Build a 1Password item JSON blob with lock fields.
    fn lock_item_json(
        email: &str,
        name: &str,
        acquired_at: &str,
        operation: &str,
        hostname: &str,
        ttl: u64,
    ) -> String {
        serde_json::json!({
            "fields": [
                {"label": FIELD_HOLDER_EMAIL, "value": email},
                {"label": FIELD_HOLDER_NAME, "value": name},
                {"label": FIELD_ACQUIRED_AT, "value": acquired_at},
                {"label": FIELD_OPERATION, "value": operation},
                {"label": FIELD_HOSTNAME, "value": hostname},
                {"label": FIELD_TTL, "value": ttl.to_string()},
            ]
        })
        .to_string()
    }

    /// Return a recent ISO timestamp (within the default TTL).
    fn fresh_timestamp() -> String {
        Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
    }

    /// Return an old ISO timestamp (well beyond default TTL).
    fn stale_timestamp() -> String {
        (Utc::now() - chrono::Duration::seconds(600))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    }

    // -- acquire ----------------------------------------------------------

    #[test]
    fn acquire_succeeds() {
        // Responses: get_current_user_details, store_item (create).
        let user_json = r#"{"email":"alice@example.com","name":"Alice"}"#;
        let op = mock_op(vec![ok_output(user_json), ok_output("")]);

        let mut lock = VaultLock::new(None);
        lock.acquire(&op, "cert_create", 300).unwrap();
        assert!(lock.held());
    }

    #[test]
    fn acquire_sets_correct_attributes() {
        let user_json = r#"{"email":"alice@example.com","name":"Alice"}"#;
        let op = mock_op(vec![ok_output(user_json), ok_output("")]);

        let mut lock = VaultLock::new(None);
        lock.acquire(&op, "cert_create", 300).unwrap();

        let calls = op.runner().calls();
        // Second call is the store_item create.
        let create_call = &calls[1];
        assert!(create_call.iter().any(|a| a == "create"));
        assert!(create_call.iter().any(|a| a == "--title=CA_Lock"));
        assert!(create_call
            .iter()
            .any(|a| a == "holder_email[text]=alice@example.com"));
        assert!(create_call
            .iter()
            .any(|a| a == "holder_name[text]=Alice"));
        assert!(create_call
            .iter()
            .any(|a: &String| a.starts_with("acquired_at[text]=")));
        assert!(create_call
            .iter()
            .any(|a| a == "operation[text]=cert_create"));
        assert!(create_call
            .iter()
            .any(|a| a == "ttl_seconds[text]=300"));
    }

    // -- release ----------------------------------------------------------

    #[test]
    fn release_deletes_without_archive() {
        let user_json = r#"{"email":"alice@example.com","name":"Alice"}"#;
        // Responses: get_current_user_details, store_item, delete_item.
        let op = mock_op(vec![ok_output(user_json), ok_output(""), ok_output("")]);

        let mut lock = VaultLock::new(None);
        lock.acquire(&op, "test", 300).unwrap();
        lock.release(&op).unwrap();

        assert!(!lock.held());
        let calls = op.runner().calls();
        let delete_call = &calls[2];
        assert!(delete_call.iter().any(|a| a == "delete"));
        assert!(!delete_call.iter().any(|a| a == "--archive"));
    }

    #[test]
    fn release_idempotent() {
        let user_json = r#"{"email":"alice@example.com","name":"Alice"}"#;
        let op = mock_op(vec![ok_output(user_json), ok_output(""), ok_output("")]);

        let mut lock = VaultLock::new(None);
        lock.acquire(&op, "test", 300).unwrap();
        lock.release(&op).unwrap();
        // Second release should be a no-op (no additional CLI call).
        lock.release(&op).unwrap();

        let calls = op.runner().calls();
        assert_eq!(calls.len(), 3); // user details + create + delete
    }

    #[test]
    fn release_ignores_item_not_found() {
        let user_json = r#"{"email":"alice@example.com","name":"Alice"}"#;
        let op = mock_op(vec![
            ok_output(user_json),
            ok_output(""),
            err_output("[ERROR] item \"CA_Lock\" not found"),
        ]);

        let mut lock = VaultLock::new(None);
        lock.acquire(&op, "test", 300).unwrap();
        // Should not error even though delete returns ItemNotFound.
        lock.release(&op).unwrap();
        assert!(!lock.held());
    }

    // -- contention -------------------------------------------------------

    #[test]
    fn vault_locked_when_held_by_another() {
        let user_json = r#"{"email":"alice@example.com","name":"Alice"}"#;
        let fresh = fresh_timestamp();
        let existing_lock = lock_item_json(
            "bob@example.com",
            "Bob",
            &fresh,
            "cert_revoke",
            "bobs-mac",
            300,
        );

        let op = mock_op(vec![
            ok_output(user_json),                    // get_current_user_details
            err_output("already exists"),            // store_item conflict
            ok_output(&existing_lock),               // get_item (read lock)
        ]);

        let mut lock = VaultLock::new(None);
        let err = lock.acquire(&op, "cert_create", 300).unwrap_err();

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
    }

    // -- stale lock breaking ----------------------------------------------

    #[test]
    fn breaks_stale_lock_and_reacquires() {
        let user_json = r#"{"email":"alice@example.com","name":"Alice"}"#;
        let stale = stale_timestamp();
        let stale_lock = lock_item_json(
            "bob@example.com",
            "Bob",
            &stale,
            "cert_create",
            "bobs-mac",
            300,
        );

        let op = mock_op(vec![
            ok_output(user_json),                    // get_current_user_details
            err_output("already exists"),            // store_item conflict
            ok_output(&stale_lock),                  // get_item (read stale lock)
            ok_output(""),                           // delete_item (break stale)
            ok_output(""),                           // store_item retry (success)
        ]);

        let mut lock = VaultLock::new(None);
        lock.acquire(&op, "cert_create", 300).unwrap();
        assert!(lock.held());
    }

    #[test]
    fn corrupt_lock_treated_as_stale() {
        let user_json = r#"{"email":"alice@example.com","name":"Alice"}"#;
        let corrupt_lock = lock_item_json(
            "bob@example.com",
            "Bob",
            "not-a-valid-date",
            "cert_create",
            "bobs-mac",
            300,
        );

        let op = mock_op(vec![
            ok_output(user_json),                    // get_current_user_details
            err_output("already exists"),            // store_item conflict
            ok_output(&corrupt_lock),                // get_item (corrupt lock)
            ok_output(""),                           // delete_item (break stale)
            ok_output(""),                           // store_item retry (success)
        ]);

        let mut lock = VaultLock::new(None);
        lock.acquire(&op, "cert_create", 300).unwrap();
        assert!(lock.held());
    }

    // -- is_stale ---------------------------------------------------------

    #[test]
    fn fresh_lock_not_stale() {
        let mut info = HashMap::new();
        info.insert(FIELD_ACQUIRED_AT.to_string(), fresh_timestamp());
        info.insert(FIELD_TTL.to_string(), "300".to_string());
        assert!(!is_stale(&info));
    }

    #[test]
    fn expired_lock_is_stale() {
        let mut info = HashMap::new();
        info.insert(FIELD_ACQUIRED_AT.to_string(), stale_timestamp());
        info.insert(FIELD_TTL.to_string(), "300".to_string());
        assert!(is_stale(&info));
    }

    #[test]
    fn missing_acquired_at_is_stale() {
        let info = HashMap::new();
        assert!(is_stale(&info));
    }

    #[test]
    fn unparseable_timestamp_is_stale() {
        let mut info = HashMap::new();
        info.insert(FIELD_ACQUIRED_AT.to_string(), "garbage".to_string());
        info.insert(FIELD_TTL.to_string(), "300".to_string());
        assert!(is_stale(&info));
    }

    // -- extract_fields ---------------------------------------------------

    #[test]
    fn extract_fields_parses_item_json() {
        let json = lock_item_json(
            "alice@example.com",
            "Alice",
            "2025-01-01T00:00:00Z",
            "test",
            "host",
            300,
        );
        let fields = extract_fields(&json);
        assert_eq!(fields.get(FIELD_HOLDER_EMAIL).unwrap(), "alice@example.com");
        assert_eq!(fields.get(FIELD_HOLDER_NAME).unwrap(), "Alice");
        assert_eq!(
            fields.get(FIELD_ACQUIRED_AT).unwrap(),
            "2025-01-01T00:00:00Z"
        );
    }

    #[test]
    fn extract_fields_returns_empty_on_bad_json() {
        let fields = extract_fields("not json");
        assert!(fields.is_empty());
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

    // -- custom lock title ------------------------------------------------

    #[test]
    fn custom_lock_title() {
        let user_json = r#"{"email":"alice@example.com","name":"Alice"}"#;
        let op = mock_op(vec![ok_output(user_json), ok_output("")]);

        let mut lock = VaultLock::new(Some("Custom_Lock"));
        lock.acquire(&op, "test", 300).unwrap();

        let calls = op.runner().calls();
        let create_call = &calls[1];
        assert!(create_call.iter().any(|a| a == "--title=Custom_Lock"));
    }
}
