use opca_core::error::OpcaError;
use opca_core::op::{CommandRunner, ShellRunner};
use opca_core::services::ca::CertificateAuthority;
use opca_core::services::database::CaConfig;

use crate::app::AppContext;
use crate::output;
use crate::{DatabaseAction, DatabaseArgs};

pub fn dispatch(args: DatabaseArgs, app: &mut AppContext<ShellRunner>) -> Result<(), OpcaError> {
    match args.action {
        DatabaseAction::ConfigGet => handle_config_get(app),
        DatabaseAction::ConfigSet { conf } => handle_config_set(app, conf),
        DatabaseAction::Export => handle_export(app),
        DatabaseAction::Rebuild {
            days,
            crl_days,
            serial,
            crl_serial,
            ca_url,
            crl_url,
        } => handle_rebuild(app, days, crl_days, serial, crl_serial, ca_url, crl_url),
        DatabaseAction::Upload { store } => handle_upload(app, store),
    }
}

fn handle_config_get<R: CommandRunner>(app: &mut AppContext<R>) -> Result<(), OpcaError> {
    let ca = app.ca.as_ref().ok_or(OpcaError::CaNotFound)?;
    let db = ca
        .ca_database
        .as_ref()
        .ok_or_else(|| OpcaError::Other("Database not loaded".into()))?;

    let config = db.get_config()?;
    output::subtitle("CA Database Configuration");
    print_config(&config);

    Ok(())
}

fn handle_config_set<R: CommandRunner>(
    app: &mut AppContext<R>,
    conf: Vec<String>,
) -> Result<(), OpcaError> {
    output::title("Updating CA Database Configuration");

    // Parse key=value pairs
    let mut updates = CaConfig::default();
    for entry in &conf {
        let parts: Vec<&str> = entry.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(OpcaError::Other(format!(
                "Invalid configuration format: '{entry}'. Expected key=value."
            )));
        }
        let key = parts[0].trim();
        let value = parts[1].trim().to_string();
        match key {
            "org" => updates.org = Some(value),
            "ou" => updates.ou = Some(value),
            "email" => updates.email = Some(value),
            "city" => updates.city = Some(value),
            "state" => updates.state = Some(value),
            "country" => updates.country = Some(value),
            "ca_url" => updates.ca_url = Some(value),
            "crl_url" => updates.crl_url = Some(value),
            "days" => {
                updates.days = Some(value.parse::<i64>().map_err(|_| {
                    OpcaError::Other(format!("Invalid integer for '{key}': {value}"))
                })?);
            }
            "crl_days" => {
                updates.crl_days = Some(value.parse::<i64>().map_err(|_| {
                    OpcaError::Other(format!("Invalid integer for '{key}': {value}"))
                })?);
            }
            "ca_public_store" => updates.ca_public_store = Some(value),
            "ca_private_store" => updates.ca_private_store = Some(value),
            "ca_backup_store" => updates.ca_backup_store = Some(value),
            "ca_aws_region" => updates.ca_aws_region = Some(value),
            "crl_batch_enabled" => {
                updates.crl_batch_enabled = Some(value.parse::<bool>().map_err(|_| {
                    OpcaError::Other(format!("Invalid boolean for '{key}': {value} (use true or false)"))
                })?);
            }
            _ => {
                return Err(OpcaError::Other(format!(
                    "Unknown configuration key: '{key}'"
                )));
            }
        }
    }

    let ca = app.ca.as_mut().ok_or(OpcaError::CaNotFound)?;

    {
        let db = ca
            .ca_database
            .as_ref()
            .ok_or_else(|| OpcaError::Other("Database not loaded".into()))?;
        db.update_config(&updates)?;
    }

    ca.store_ca_database()?;

    let db = ca
        .ca_database
        .as_ref()
        .ok_or_else(|| OpcaError::Other("Database not loaded".into()))?;
    let config = db.get_config()?;
    output::print_result("Configuration updated", true);
    print_config(&config);

    Ok(())
}

fn handle_export<R: CommandRunner>(app: &mut AppContext<R>) -> Result<(), OpcaError> {
    let ca = app.ca.as_ref().ok_or(OpcaError::CaNotFound)?;
    let db = ca
        .ca_database
        .as_ref()
        .ok_or_else(|| OpcaError::Other("Database not loaded".into()))?;

    let data = db.export_database()?;
    let text = String::from_utf8_lossy(&data);
    print!("{text}");

    Ok(())
}

fn handle_rebuild<R: CommandRunner>(
    app: &mut AppContext<R>,
    days: i64,
    crl_days: i64,
    serial: Option<i64>,
    crl_serial: Option<i64>,
    ca_url: Option<String>,
    crl_url: Option<String>,
) -> Result<(), OpcaError> {
    output::title("Rebuilding CA Database");

    let config = CaConfig {
        next_serial: serial,
        next_crl_serial: crl_serial,
        days: Some(days),
        crl_days: Some(crl_days),
        ca_url,
        crl_url,
        ..CaConfig::default()
    };

    let op = app.take_op()?;
    let mut ca = CertificateAuthority::rebuild_database(op, &config)?;
    ca.store_ca_database()?;
    output::print_result("Database rebuilt and stored", true);
    app.ca = Some(ca);

    Ok(())
}

fn handle_upload<R: CommandRunner>(
    app: &mut AppContext<R>,
    stores: Vec<String>,
) -> Result<(), OpcaError> {
    output::title("Uploading CA Database");

    let ca = app.ca.as_ref().ok_or(OpcaError::CaNotFound)?;

    if stores.is_empty() {
        ca.upload_ca_database("")?;
        output::print_result("Upload to default private store", true);
    } else {
        for uri in &stores {
            ca.upload_ca_database(uri)?;
            output::print_result(&format!("Upload to {uri}"), true);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn print_config(config: &CaConfig) {
    let field = |label: &str, value: &Option<String>| {
        output::info(label, value.as_deref().unwrap_or("(not set)"));
    };
    let ifield = |label: &str, value: &Option<i64>| {
        output::info(
            label,
            &value
                .map(|v| v.to_string())
                .unwrap_or_else(|| "(not set)".to_string()),
        );
    };

    ifield("Next Serial", &config.next_serial);
    ifield("Next CRL Serial", &config.next_crl_serial);
    field("Organisation", &config.org);
    field("Organisational Unit", &config.ou);
    field("Email", &config.email);
    field("City", &config.city);
    field("State", &config.state);
    field("Country", &config.country);
    field("CA URL", &config.ca_url);
    field("CRL URL", &config.crl_url);
    ifield("Days", &config.days);
    ifield("CRL Days", &config.crl_days);
    field("Public Store", &config.ca_public_store);
    field("Private Store", &config.ca_private_store);
    field("Backup Store", &config.ca_backup_store);
    field("AWS Region", &config.ca_aws_region);
    output::info("CRL Batches", if config.crl_batch_enabled == Some(true) { "on" } else { "off" });
}
