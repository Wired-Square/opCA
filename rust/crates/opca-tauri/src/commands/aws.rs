//! AWS credential selection.
//!
//! The AWS access key is per-user, per-machine state: several operators share
//! one CA (and therefore one CA database in the shared vault), but each has
//! their own AWS credentials. The selection is stored locally by
//! [`opca_core::settings`], keyed by 1Password account so operators working
//! across tenants keep a separate choice for each.
//!
//! The bucket's region, by contrast, is a property of the CA and lives in the
//! shared config (`ca_aws_region`).

use log::{debug, info, warn};
use serde::Serialize;
use tauri::State;

use opca_core::op::ShellRunner;
use opca_core::services::storage::{
    get_aws_credentials_for_item, list_aws_credential_items, AwsItemRef,
};
use opca_core::settings;

use crate::state::AppState;

/// The AWS credential currently selected for the connected account.
#[derive(Debug, Serialize)]
pub struct AwsCredentialSelection {
    /// Selected item ID, or `None` when the user has not chosen one yet.
    pub item_id: Option<String>,
    /// The 1Password account the selection applies to.
    pub account: Option<String>,
}

#[tauri::command]
pub async fn list_aws_credentials(
    state: State<'_, AppState>,
) -> Result<Vec<AwsItemRef>, String> {
    info!("[tauri] list_aws_credentials");

    // `op item list` takes seconds on a large account, so copy the account
    // out and release the connection lock before spawning it — otherwise
    // every other command stalls for the duration.
    let account = state.with_op(|op| Ok(op.account().map(String::from)))?;

    list_aws_credential_items(&ShellRunner, account.as_deref()).map_err(|e| {
        warn!("[tauri] list_aws_credentials failed: {e}");
        e.to_string()
    })
}

#[tauri::command]
pub async fn get_aws_credential(
    state: State<'_, AppState>,
) -> Result<AwsCredentialSelection, String> {
    debug!("[tauri] get_aws_credential");
    state.with_op(|op| {
        Ok(AwsCredentialSelection {
            item_id: settings::aws_credential_item(op.account()),
            account: op.account().map(String::from),
        })
    })
}

/// Select (or with `item_id: None`, clear) this user's AWS credential.
///
/// A selection is validated by reading the item before it is saved, so a
/// mis-picked item fails here rather than at the next upload.
#[tauri::command]
pub async fn set_aws_credential(
    state: State<'_, AppState>,
    item_id: Option<String>,
) -> Result<(), String> {
    info!("[tauri] set_aws_credential");

    state
        .with_op(|op| {
            if let Some(ref id) = item_id {
                get_aws_credentials_for_item(op.runner(), op.account(), id)
                    .map_err(|e| e.to_string())?;
            }

            settings::set_aws_credential_item(op.account(), item_id.as_deref())
                .map_err(|e| e.to_string())
        })
        .map_err(|e| {
            warn!("[tauri] set_aws_credential failed: {e}");
            state.log_err("set_aws_credential", Some(e.clone()));
            e
        })?;

    let detail = match item_id {
        Some(_) => "AWS credential selected",
        None => "AWS credential cleared",
    };
    state.log_ok("set_aws_credential", Some(detail.to_string()));
    Ok(())
}
