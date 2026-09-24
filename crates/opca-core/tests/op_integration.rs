//! Integration tests for the `Op` struct against a real 1Password CLI session.
//!
//! These tests are guarded by the `OPCA_INTEGRATION_TEST` environment variable.
//! To run them you need:
//! - `op` CLI installed and on `$PATH`
//! - A signed-in 1Password session (or biometric unlock configured)
//! - A test vault accessible to the signed-in account
//!
//! Usage:
//!   OPCA_INTEGRATION_TEST=1 OPCA_TEST_VAULT=MyVault cargo test -p opca-core --test op_integration

use opca_core::op::{list_accounts_standalone, whoami_standalone, Op};

/// Return the test vault name from `OPCA_TEST_VAULT`, or a sensible default.
fn test_vault() -> String {
    std::env::var("OPCA_TEST_VAULT").unwrap_or_else(|_| "Private".to_string())
}

/// Return the optional account from `OPCA_TEST_ACCOUNT`.
fn test_account() -> Option<String> {
    std::env::var("OPCA_TEST_ACCOUNT").ok()
}

/// Skip the test if `OPCA_INTEGRATION_TEST` is not set.
macro_rules! skip_unless_integration {
    () => {
        if std::env::var("OPCA_INTEGRATION_TEST").is_err() {
            eprintln!("Skipping integration test: set OPCA_INTEGRATION_TEST=1 to run");
            return;
        }
    };
}

#[test]
fn op_new_succeeds_with_valid_vault() {
    skip_unless_integration!();
    let op = Op::new(test_vault(), test_account(), None);
    assert!(op.is_ok(), "Op::new failed: {:?}", op.unwrap_err());
}

#[test]
fn op_new_fails_with_nonexistent_vault() {
    skip_unless_integration!();
    let result = Op::new("__nonexistent_vault_99999__", test_account(), None);
    assert!(result.is_err());
}

#[test]
fn whoami_returns_nonempty_string() {
    skip_unless_integration!();
    let op = Op::new(test_vault(), test_account(), None).unwrap();
    let who = op.whoami().unwrap();
    assert!(!who.trim().is_empty(), "whoami returned empty string");
}

/// The settings account key is a `user_uuid` from `op account list`, matched
/// against `op whoami` when no account was given — so the two must agree on
/// that field. This is the only place the real payload shape is checked.
///
/// Note `whoami` reports the url as a full `https://host/` while `account list`
/// reports a bare host, so only the UUID is safe to match on.
#[test]
fn whoami_user_uuid_appears_in_the_account_list() {
    skip_unless_integration!();
    // Establish a session the way production does before settings ever asks.
    Op::new(test_vault(), test_account(), None).expect("could not sign in");

    let who = whoami_standalone().expect("op whoami --format=json failed");
    assert!(!who.user_uuid.is_empty(), "whoami reported no user_uuid: {who:?}");

    let accounts = list_accounts_standalone().expect("op account list failed");
    assert!(
        accounts.iter().any(|a| a.user_uuid == who.user_uuid),
        "whoami user_uuid {} is in no configured account: {accounts:?}",
        who.user_uuid,
    );
}

#[test]
fn vault_list_returns_at_least_one() {
    skip_unless_integration!();
    let op = Op::new(test_vault(), test_account(), None).unwrap();
    let vaults = op.vault_list().unwrap();
    assert!(!vaults.is_empty(), "vault_list returned no vaults");
}

#[test]
fn item_exists_returns_false_for_nonexistent() {
    skip_unless_integration!();
    let op = Op::new(test_vault(), test_account(), None).unwrap();
    assert!(!op.item_exists("__nonexistent_item_99999__"));
}
