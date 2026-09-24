//! Per-user, per-machine local settings.
//!
//! These are deliberately **not** stored in the CA database: that database
//! lives in the shared 1Password vault, so anything written there applies to
//! every user of the CA.  Settings here are personal to one operator on one
//! machine — most importantly, which 1Password item holds *their* AWS access
//! key.  Several people share a CA but each has their own AWS credentials.
//!
//! Settings are keyed per 1Password account, so that operators who work across
//! multiple tenants keep a separate selection for each. See [`account_key`] for
//! what "per account" means precisely — it is not the string the user typed.
//!
//! Stored as JSON at the platform config directory, e.g. on macOS
//! `~/Library/Application Support/opca/settings.json`.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use log::{debug, warn};
use serde::{Deserialize, Serialize};

use crate::error::OpcaError;
use crate::op::{self, AccountInfo};

/// Directory name under the platform config directory.
const SETTINGS_DIR: &str = "opca";
/// Settings file name.
const SETTINGS_FILE: &str = "settings.json";
/// Key used when the account cannot be identified at all.
const DEFAULT_ACCOUNT_KEY: &str = "default";

/// Local settings for the current user.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Settings {
    /// 1Password user UUID → item ID of that operator's AWS access key.
    #[serde(default)]
    aws_credential_items: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// Identifying the account
// ---------------------------------------------------------------------------

/// Match an `--account` identifier against one account's aliases.
fn is_alias_of(identifier: &str, account: &AccountInfo) -> bool {
    [&account.user_uuid, &account.account_uuid, &account.url]
        .iter()
        .any(|alias| !alias.is_empty() && alias.eq_ignore_ascii_case(identifier))
}

/// Match an `--account` identifier against a known account, returning its user
/// UUID.
///
/// `op` accepts the sign-in address, the account UUID or the user UUID for the
/// same account, and the GUI and CLI pass different ones — so the identifier
/// itself makes a poor key. The user UUID is the one stable choice: a row in
/// `op account list` is an (account, user) pair, and the selected item lives in
/// a vault only that user can read.
///
/// `None` when nothing matches, or when the identifier is a sign-in address
/// shared by two configured accounts — `op --account` cannot resolve that
/// either, so there is nothing to be consistent with.
fn match_alias(identifier: &str, accounts: &[AccountInfo]) -> Option<String> {
    let identifier = identifier.trim();
    let mut matches = accounts.iter().filter(|a| is_alias_of(identifier, a));
    let first = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(first.user_uuid.clone()).filter(|uuid| !uuid.is_empty())
}

/// Ask `op` which account an identifier names, for the forms there is nothing
/// in `op account list` to match against — a *shorthand* above all, which it
/// does not report at all.
///
/// Memoised per identifier, misses included: this sits on the S3 upload path,
/// and every key in the settings file goes through it.
fn account_id_via_op(identifier: &str) -> Option<String> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Mutex::default);

    {
        let seen = cache.lock().ok()?;
        if let Some(hit) = seen.get(identifier) {
            return hit.clone();
        }
    }

    let id = op::get_account_standalone(identifier)
        .map(|account| account.id)
        .map_err(|e| debug!("[settings] `op account get {identifier}` found nothing: {e}"))
        .ok();
    cache.lock().ok()?.insert(identifier.to_string(), id.clone());
    id
}

/// The stable identity behind an account identifier — or an existing settings
/// key, which is an identifier someone passed to `op --account` once.
///
/// `None` for anything that names no single account, which includes the
/// `"default"` key and entries left behind by an account since removed.
fn canonical_key(identifier: &str) -> Option<String> {
    let accounts = configured_accounts();
    match_alias(identifier, accounts)
        .or_else(|| match_alias(&account_id_via_op(identifier)?, accounts))
}

/// The accounts configured in the local `op` CLI, read once per process.
///
/// `op account list` reads local config and needs no sign-in, so this is cheap
/// — but it does sit on the S3 upload path, hence the memo. An account added
/// mid-session is not picked up; the key then falls back to the identifier, as
/// it did before this was resolved at all.
fn configured_accounts() -> &'static [AccountInfo] {
    static ACCOUNTS: OnceLock<Vec<AccountInfo>> = OnceLock::new();
    ACCOUNTS.get_or_init(|| {
        op::list_accounts_standalone().unwrap_or_else(|e| {
            warn!("[settings] could not list 1Password accounts: {e}");
            Vec::new()
        })
    })
}

/// The user UUID `op` is signed in as, read once per process.
///
/// Only consulted when no account was given explicitly — by which point the
/// caller has already been through `Op::new`, so the session is live.
fn signed_in_user() -> Option<&'static str> {
    static USER: OnceLock<Option<String>> = OnceLock::new();
    USER.get_or_init(|| {
        match op::whoami_standalone() {
            Ok(who) if !who.user_uuid.is_empty() => Some(who.user_uuid),
            Ok(_) => None,
            Err(e) => {
                warn!("[settings] could not identify the signed-in account: {e}");
                None
            }
        }
    })
    .as_deref()
}

/// The settings map key for `account`.
///
/// Falls back to the lowercased identifier when it cannot be resolved (an `op`
/// *shorthand*, which `op account list` does not report, lands here), and to
/// `"default"` when there is no identifier and no readable session. Neither
/// fails — they only stop converging.
fn account_key(account: Option<&str>) -> String {
    match account.map(str::trim).filter(|a| !a.is_empty()) {
        Some(acct) => canonical_key(acct).unwrap_or_else(|| acct.to_lowercase()),
        None => signed_in_user()
            .map(str::to_string)
            .unwrap_or_else(|| DEFAULT_ACCOUNT_KEY.to_string()),
    }
}

/// Human-readable name for an account identifier, for surfaces that echo the
/// account back to the user — the keys themselves are opaque UUIDs.
pub fn account_label(account: Option<&str>) -> Option<String> {
    let uuid = match account.map(str::trim).filter(|a| !a.is_empty()) {
        Some(acct) => canonical_key(acct)?,
        None => signed_in_user()?.to_string(),
    };
    configured_accounts()
        .iter()
        .find(|a| a.user_uuid == uuid)
        .map(|a| format!("{} ({})", a.email, a.url))
}

/// Rekey entries stored under an older identifier for a known account.
///
/// Before the key was resolved, it was whatever string had been passed to
/// `op --account` — a shorthand, an address, a UUID — so one operator could
/// accumulate several entries for one account. Each key is put back through
/// `canonical`, the same resolution a lookup uses, and entries that name the
/// same account merge.
///
/// Keys arrive sorted (`BTreeMap`), so which of two conflicting entries
/// survives does not vary between runs; the other is logged rather than
/// silently dropped.
fn migrate(settings: &mut Settings, canonical: impl Fn(&str) -> Option<String>) {
    let rekeys: Vec<(String, String)> = settings
        .aws_credential_items
        .keys()
        .filter_map(|key| {
            canonical(key)
                .filter(|resolved| resolved != key)
                .map(|resolved| (key.clone(), resolved))
        })
        .collect();

    for (old, new) in rekeys {
        let Some(item) = settings.aws_credential_items.remove(&old) else {
            continue;
        };
        match settings.aws_credential_items.get(&new) {
            Some(kept) if kept != &item => warn!(
                "[settings] '{old}' also selected AWS credential '{item}' for this \
                 account; keeping '{kept}'"
            ),
            Some(_) => {}
            None => {
                debug!("[settings] adopting AWS credential from '{old}'");
                settings.aws_credential_items.insert(new, item);
            }
        }
    }
}

/// Path to the settings file. Reading must not create anything, so the
/// parent directory is created by [`save`] instead.
pub fn settings_path() -> Result<PathBuf, OpcaError> {
    Ok(dirs::config_dir()
        .ok_or_else(|| OpcaError::Other("Could not determine the user config directory".into()))?
        .join(SETTINGS_DIR)
        .join(SETTINGS_FILE))
}

/// Load settings, falling back to defaults when the file is missing or
/// unreadable.  A corrupt settings file should never stop the app starting.
///
/// Entries written before the key was resolved are rekeyed on the way through,
/// so a read sees them immediately; the file itself is rewritten by the next
/// [`save`].
fn load() -> Settings {
    let Ok(path) = settings_path() else {
        return Settings::default();
    };

    let mut settings: Settings = match std::fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_else(|e| {
            warn!("[settings] ignoring invalid {}: {e}", path.display());
            Settings::default()
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Settings::default(),
        Err(e) => {
            warn!("[settings] could not read {}: {e}", path.display());
            Settings::default()
        }
    };

    migrate(&mut settings, canonical_key);
    settings
}

/// Persist settings, replacing the existing file.
fn save(settings: &Settings) -> Result<(), OpcaError> {
    let path = settings_path()?;
    let json = serde_json::to_string_pretty(settings)
        .map_err(|e| OpcaError::Other(format!("Could not serialise settings: {e}")))?;

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| {
            OpcaError::Other(format!("Could not create {}: {e}", dir.display()))
        })?;
    }

    std::fs::write(&path, json)
        .map_err(|e| OpcaError::Other(format!("Could not write {}: {e}", path.display())))?;

    debug!("[settings] saved {}", path.display());
    Ok(())
}

/// The AWS credential item ID selected for `account`, if any.
///
/// `account` is any identifier `op --account` accepts — the GUI and the CLI
/// pass different ones for the same account, and [`account_key`] resolves them
/// to the same entry.
pub fn aws_credential_item(account: Option<&str>) -> Option<String> {
    load().aws_credential_items.get(&account_key(account)).cloned()
}

/// Select (or with `None`, clear) the AWS credential item for `account`.
pub fn set_aws_credential_item(
    account: Option<&str>,
    item_id: Option<&str>,
) -> Result<(), OpcaError> {
    let mut settings = load();
    let key = account_key(account);

    match item_id.map(str::trim).filter(|id| !id.is_empty()) {
        Some(id) => settings.aws_credential_items.insert(key, id.to_string()),
        None => settings.aws_credential_items.remove(&key),
    };

    save(&settings)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn account(url: &str, email: &str, account_uuid: &str, user_uuid: &str) -> AccountInfo {
        AccountInfo {
            url: url.to_string(),
            email: email.to_string(),
            account_uuid: account_uuid.to_string(),
            user_uuid: user_uuid.to_string(),
        }
    }

    /// Two personal accounts share a sign-in address — the case that forced the
    /// GUI to send a UUID in the first place.
    fn accounts() -> Vec<AccountInfo> {
        vec![
            account("wiredsquare.1password.com", "alex@wiredsquare.com", "W-ACCT", "W-USER"),
            account("my.1password.com", "alex@wiredsquare.com", "A-ACCT", "A-USER"),
            account("my.1password.com", "alex@ferrara.com.au", "B-ACCT", "B-USER"),
        ]
    }

    // -- match_alias --------------------------------------------------

    #[test]
    fn test_match_alias_accepts_every_identifier_in_the_list() {
        let all = accounts();
        for identifier in ["wiredsquare.1password.com", "W-ACCT", "W-USER"] {
            assert_eq!(match_alias(identifier, &all).as_deref(), Some("W-USER"), "{identifier}");
        }
    }

    #[test]
    fn test_match_alias_ignores_case_and_whitespace() {
        assert_eq!(
            match_alias("  WiredSquare.1Password.com ", &accounts()).as_deref(),
            Some("W-USER"),
        );
    }

    #[test]
    fn test_match_alias_declines_a_shared_address() {
        // `op --account my.1password.com` fails too, so there is nothing to be
        // consistent with — better to leave the entry where the user put it.
        assert_eq!(match_alias("my.1password.com", &accounts()), None);
        // The UUIDs still tell them apart.
        assert_eq!(match_alias("A-ACCT", &accounts()).as_deref(), Some("A-USER"));
        assert_eq!(match_alias("B-USER", &accounts()).as_deref(), Some("B-USER"));
    }

    #[test]
    fn test_match_alias_declines_the_unknown() {
        // A shorthand is not in the list at all — `canonical_key` escalates to
        // `op account get` for these.
        assert_eq!(match_alias("wired", &accounts()), None);
        assert_eq!(match_alias("wiredsquare.1password.com", &[]), None);
    }

    #[test]
    fn test_match_alias_ignores_blank_aliases() {
        // An older `op` omits the UUIDs; an empty field must not match an
        // empty identifier and claim an unrelated account.
        let sparse = vec![account("wiredsquare.1password.com", "alex@wiredsquare.com", "", "")];
        assert_eq!(match_alias("", &sparse), None);
        assert_eq!(match_alias("wiredsquare.1password.com", &sparse), None);
    }

    // -- migrate ------------------------------------------------------

    fn with_entries(entries: &[(&str, &str)]) -> Settings {
        Settings {
            aws_credential_items: entries
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    /// Stand-in for the real resolver: the list match, plus the one shorthand
    /// `op account get` would resolve for us.
    fn resolver(key: &str) -> Option<String> {
        match_alias(key, &accounts())
            .or_else(|| (key == "wired").then(|| "W-USER".to_string()))
    }

    #[test]
    fn test_migrate_adopts_an_address_keyed_entry() {
        let mut settings = with_entries(&[("wiredsquare.1password.com", "item-1")]);
        migrate(&mut settings, resolver);
        assert_eq!(settings.aws_credential_items.get("W-USER"), Some(&"item-1".into()));
        assert!(!settings.aws_credential_items.contains_key("wiredsquare.1password.com"));
    }

    #[test]
    fn test_migrate_adopts_an_account_uuid_keyed_entry() {
        let mut settings = with_entries(&[("A-ACCT", "item-2")]);
        migrate(&mut settings, resolver);
        assert_eq!(settings.aws_credential_items.get("A-USER"), Some(&"item-2".into()));
    }

    #[test]
    fn test_migrate_merges_a_shorthand_and_an_address() {
        // The real-world case: `opca -a wired aws use` and the GUI's address,
        // one account, one item, two entries.
        let mut settings = with_entries(&[
            ("wired", "item-1"),
            ("wiredsquare.1password.com", "item-1"),
        ]);
        migrate(&mut settings, resolver);
        assert_eq!(settings.aws_credential_items.get("W-USER"), Some(&"item-1".into()));
        assert_eq!(settings.aws_credential_items.len(), 1);
    }

    #[test]
    fn test_migrate_keeps_the_canonical_entry_when_aliases_disagree() {
        let mut settings = with_entries(&[
            ("W-USER", "canonical"),
            ("W-ACCT", "from-gui"),
            ("wiredsquare.1password.com", "from-cli"),
        ]);
        migrate(&mut settings, resolver);
        assert_eq!(settings.aws_credential_items.get("W-USER"), Some(&"canonical".into()));
        assert_eq!(settings.aws_credential_items.len(), 1);
    }

    #[test]
    fn test_migrate_resolves_conflicting_aliases_the_same_way_every_run() {
        // Nothing is canonical yet and the two disagree, so one has to lose —
        // sorted key order decides, not whatever the map iterates first.
        let entries = [("W-ACCT", "from-gui"), ("wiredsquare.1password.com", "from-cli")];
        for _ in 0..3 {
            let mut settings = with_entries(&entries);
            migrate(&mut settings, resolver);
            assert_eq!(settings.aws_credential_items.get("W-USER"), Some(&"from-gui".into()));
            assert_eq!(settings.aws_credential_items.len(), 1);
        }
    }

    #[test]
    fn test_migrate_leaves_unrecognised_keys_alone() {
        let mut settings = with_entries(&[
            (DEFAULT_ACCOUNT_KEY, "item-3"),
            ("some.other.1password.com", "item-4"),
        ]);
        migrate(&mut settings, resolver);
        assert_eq!(settings.aws_credential_items.get(DEFAULT_ACCOUNT_KEY), Some(&"item-3".into()));
        assert_eq!(settings.aws_credential_items.get("some.other.1password.com"), Some(&"item-4".into()));
    }

    #[test]
    fn test_migrate_is_a_no_op_when_nothing_resolves() {
        // `op account list` failing must never mangle the file.
        let before = with_entries(&[("wiredsquare.1password.com", "item-1")]);
        let mut settings = before.clone();
        migrate(&mut settings, |_| None);
        assert_eq!(settings.aws_credential_items, before.aws_credential_items);
    }

    #[test]
    fn test_migrate_is_idempotent() {
        let mut settings = with_entries(&[("wiredsquare.1password.com", "item-1")]);
        migrate(&mut settings, resolver);
        let once = settings.clone();
        migrate(&mut settings, resolver);
        assert_eq!(settings.aws_credential_items, once.aws_credential_items);
    }

    #[test]
    fn test_settings_round_trip() {
        let mut settings = Settings::default();
        settings
            .aws_credential_items
            .insert("xentro.1password.com".into(), "abc123".into());

        let json = serde_json::to_string(&settings).unwrap();
        let parsed: Settings = serde_json::from_str(&json).unwrap();

        assert_eq!(
            parsed.aws_credential_items.get("xentro.1password.com"),
            Some(&"abc123".to_string())
        );
    }

    #[test]
    fn test_settings_tolerates_missing_keys() {
        let parsed: Settings = serde_json::from_str("{}").unwrap();
        assert!(parsed.aws_credential_items.is_empty());
    }
}
