use std::collections::HashMap;

use opca_core::constants::DEFAULT_OP_CONF;
use opca_core::error::OpcaError;
use opca_core::op::{CommandRunner, ShellRunner};
use opca_core::services::backup::{decrypt_payload, encrypt_payload};
use opca_core::services::vault::{BackupPayload, VaultBackup};

use crate::app::AppContext;
use crate::output;
use crate::{VaultAction, VaultArgs};

pub fn dispatch(args: VaultArgs, app: &mut AppContext<ShellRunner>) -> Result<(), OpcaError> {
    match args.action {
        VaultAction::Backup { output: out, password } => handle_backup(app, out, password),
        VaultAction::Restore { input, password } => handle_restore(app, input, password),
        VaultAction::Info { input, password } => handle_info(input, password),
    }
}

fn handle_backup<R: CommandRunner>(
    app: &mut AppContext<R>,
    output_path: Option<String>,
    password: Option<String>,
) -> Result<(), OpcaError> {
    output::title("Creating Vault Backup");

    let password = match password {
        Some(p) => p,
        None => super::cert::get_password("Enter backup password: ")?,
    };

    let op = app.op()?;

    // Default output path
    let path = output_path.unwrap_or_else(|| {
        let vault_name = &op.vault;
        let timestamp = chrono::Utc::now().format("%Y-%m-%d_%H%M%S");
        let home = dirs_home().unwrap_or_else(|| ".".to_string());
        format!("{home}/{vault_name}-{timestamp}.opca")
    });

    let vb = VaultBackup::new(op, &DEFAULT_OP_CONF);
    let payload = vb.create_backup()?;

    output::info("Vault", &payload.metadata.vault_name);
    output::info("Items", &payload.metadata.item_count.to_string());

    let json_bytes = serde_json::to_vec(&payload)
        .map_err(|e| OpcaError::Other(format!("Failed to serialise backup: {e}")))?;

    let encrypted = encrypt_payload(&json_bytes, &password)?;

    write_backup_file(&path, &encrypted)?;
    output::print_result(&format!("Backup saved to {path}"), true);

    Ok(())
}

fn handle_restore<R: CommandRunner>(
    app: &mut AppContext<R>,
    input: String,
    password: Option<String>,
) -> Result<(), OpcaError> {
    output::title("Restoring Vault from Backup");

    let data = std::fs::read(&input)?;

    let password = match password {
        Some(p) => p,
        None => super::cert::get_password_single("Enter backup password: ")?,
    };

    let plaintext = decrypt_payload(&data, &password)?;
    let payload: BackupPayload = serde_json::from_slice(&plaintext)
        .map_err(|e| OpcaError::Other(format!("Invalid backup format: {e}")))?;

    output::info("Source Vault", &payload.metadata.vault_name);
    output::info("Backup Date", &payload.metadata.backup_date);
    output::info("Items", &payload.metadata.item_count.to_string());

    let op = app.op()?;
    let vb = VaultBackup::new(op, &DEFAULT_OP_CONF);

    let on_progress = |item_type: &str, title: &str| {
        println!("  Restoring {item_type}: {title}");
    };

    let counts = vb.restore_backup(&payload, Some(&on_progress))?;

    println!();
    let total: usize = counts.values().sum();
    output::print_result(&format!("Restored {total} item(s)"), true);

    print_item_counts(&counts);

    Ok(())
}

fn handle_info(input: String, password: Option<String>) -> Result<(), OpcaError> {
    let data = std::fs::read(&input)?;

    let password = match password {
        Some(p) => p,
        None => super::cert::get_password_single("Enter backup password: ")?,
    };

    let plaintext = decrypt_payload(&data, &password)?;
    let payload: BackupPayload = serde_json::from_slice(&plaintext)
        .map_err(|e| OpcaError::Other(format!("Invalid backup format: {e}")))?;

    output::subtitle("Backup Information");
    output::info("OPCA Version", &payload.metadata.opca_version);
    output::info("Vault Name", &payload.metadata.vault_name);
    output::info("Backup Date", &payload.metadata.backup_date);
    output::info("Item Count", &payload.metadata.item_count.to_string());

    // Count by type
    let mut type_counts: HashMap<String, usize> = HashMap::new();
    for item in &payload.items {
        *type_counts.entry(item.item_type.clone()).or_insert(0) += 1;
    }

    print_item_counts(&type_counts);

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn print_item_counts(counts: &HashMap<String, usize>) {
    if counts.is_empty() {
        return;
    }

    println!();
    let mut sorted: Vec<_> = counts.iter().collect();
    sorted.sort_by_key(|(k, _)| (*k).clone());
    for (item_type, count) in sorted {
        output::info(&format!("  {item_type}"), &count.to_string());
    }
}

fn write_backup_file(path: &str, data: &[u8]) -> Result<(), OpcaError> {
    use std::io::Write;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| OpcaError::Io(format!("Failed to create '{path}': {e}")))?;
        file.write_all(data)
            .map_err(|e| OpcaError::Io(format!("Failed to write '{path}': {e}")))?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
            .map_err(|e| OpcaError::Io(format!("Failed to write '{path}': {e}")))?;
    }

    Ok(())
}

fn dirs_home() -> Option<String> {
    // Simple home directory detection without adding a dependency
    std::env::var("HOME").ok()
}
