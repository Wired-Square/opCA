//! AWS credential selection.
//!
//! Mirrors the GUI's picker: the AWS access key is per-user, per-machine
//! state (several operators share one CA but each has their own key), stored
//! locally by [`opca_core::settings`] and keyed by 1Password account.
//!
//! The region is *not* here — it belongs to the bucket, so it lives in the
//! shared CA config (`opca database config-set ca_aws_region ...`).

use opca_core::error::OpcaError;
use opca_core::op::ShellRunner;
use opca_core::services::storage::{get_aws_credentials_for_item, list_aws_credential_items};
use opca_core::settings;

use crate::app::AppContext;
use crate::output;
use crate::{AwsAction, AwsArgs};

pub fn dispatch(args: AwsArgs, app: &mut AppContext<ShellRunner>) -> Result<(), OpcaError> {
    match args.action {
        AwsAction::List { pattern } => list(app, pattern),
        AwsAction::Show => show(app),
        AwsAction::Use { item } => select(app, item),
        AwsAction::Clear => clear(app),
    }
}

fn list(app: &AppContext<ShellRunner>, pattern: Option<String>) -> Result<(), OpcaError> {
    let op = app.op()?;
    let all = list_aws_credential_items(op.runner(), op.account())?;
    let selected = settings::aws_credential_item(op.account());

    let needle = pattern.unwrap_or_default().to_lowercase();
    let items: Vec<_> = all
        .iter()
        .filter(|i| i.title.to_lowercase().contains(&needle))
        .collect();

    output::title("Candidate AWS credential items");
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|item| {
            vec![
                if Some(&item.id) == selected.as_ref() { "*".into() } else { String::new() },
                item.id.clone(),
                item.title.clone(),
                item.vault.clone(),
            ]
        })
        .collect();
    output::print_table(&["", "ID", "TITLE", "VAULT"], &rows);

    println!();
    output::info(
        "Showing",
        &format!("{} of {} item(s)", items.len(), all.len()),
    );
    output::info("Select with", "opca aws use <id-or-title>");
    Ok(())
}

fn show(app: &AppContext<ShellRunner>) -> Result<(), OpcaError> {
    let op = app.op()?;
    let account = op.account().unwrap_or("(default)");

    output::title("Selected AWS credential");
    output::info("Account", account);

    match settings::aws_credential_item(op.account()) {
        Some(item_id) => {
            let creds = get_aws_credentials_for_item(op.runner(), op.account(), &item_id)?;
            output::info("Item", &item_id);
            output::info("Access key ID", &creds.access_key_id);
            output::info("Settings file", &settings::settings_path()?.display().to_string());
        }
        None => output::warning("No AWS credential selected — run 'opca aws use <item>'"),
    }
    Ok(())
}

fn select(app: &AppContext<ShellRunner>, item: String) -> Result<(), OpcaError> {
    let op = app.op()?;

    // Validate by reading the item, so a bad pick fails now rather than at
    // the next upload. `op item get` accepts an ID or a title.
    let creds = get_aws_credentials_for_item(op.runner(), op.account(), &item)?;
    settings::set_aws_credential_item(op.account(), Some(&item))?;

    output::print_result(
        &format!("Using AWS credential '{item}' ({})", creds.access_key_id),
        true,
    );
    Ok(())
}

fn clear(app: &AppContext<ShellRunner>) -> Result<(), OpcaError> {
    let op = app.op()?;
    settings::set_aws_credential_item(op.account(), None)?;
    output::print_result("AWS credential selection cleared", true);
    Ok(())
}
