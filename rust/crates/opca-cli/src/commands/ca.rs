use opca_core::error::OpcaError;
use opca_core::op::{CommandRunner, ShellRunner};
use opca_core::services::ca::{CaExpiryWarning, CertificateAuthority};
use opca_core::services::database::CaConfig;

use crate::app::{with_lock, AppContext};
use crate::output;
use crate::{CaAction, CaArgs};

pub fn dispatch(args: CaArgs, app: &mut AppContext<ShellRunner>) -> Result<(), OpcaError> {
    match args.action {
        CaAction::Init {
            cn,
            org,
            ca_days,
            crl_days,
            days,
            email,
            ou,
            city,
            state,
            country,
            ca_url,
            crl_url,
        } => handle_init(
            app, cn, org, ca_days, crl_days, days, email, ou, city, state, country, ca_url,
            crl_url,
        ),
        CaAction::Import {
            cert_file,
            key_file,
            days,
            crl_days,
            serial,
            crl_serial,
            ca_url,
            crl_url,
        } => handle_import(
            app, cert_file, key_file, days, crl_days, serial, crl_serial, ca_url, crl_url,
        ),
        CaAction::Export {
            with_key,
            cert_only: _,
            to_stdout,
            cert_out,
            key_out,
        } => handle_export(app, with_key, to_stdout, cert_out, key_out),
        CaAction::List {
            all: _,
            expired,
            revoked,
            expiring,
            valid,
            cn,
            serial,
        } => handle_list(app, expired, revoked, expiring, valid, cn, serial),
        CaAction::Resign { ca_days } => handle_resign(app, ca_days),
        CaAction::Upload { store } => handle_upload(app, store),
    }
}

fn handle_init<R: CommandRunner>(
    app: &mut AppContext<R>,
    cn: String,
    org: String,
    ca_days: i64,
    crl_days: i64,
    days: i64,
    email: Option<String>,
    ou: Option<String>,
    city: Option<String>,
    state: Option<String>,
    country: Option<String>,
    ca_url: Option<String>,
    crl_url: Option<String>,
) -> Result<(), OpcaError> {
    output::title("Initialising the Certificate Authority");

    let init_config = CaConfig {
        cn: Some(cn),
        ca_days: Some(ca_days),
        next_serial: Some(1),
        next_crl_serial: Some(1),
        org: Some(org),
        ou,
        email,
        city,
        state,
        country,
        ca_url,
        crl_url,
        days: Some(days),
        crl_days: Some(crl_days),
        schema_version: None,
        ca_public_store: None,
        ca_private_store: None,
        ca_backup_store: None,
    };

    with_lock(app, "ca_init", |app| {
        let op = app.take_op()?;
        let ca = CertificateAuthority::init(op, &init_config)?;
        let valid = ca.is_valid().unwrap_or(false);
        output::print_result("CA certificate validation", valid);
        app.ca = Some(ca);
        Ok(())
    })
}

fn handle_import<R: CommandRunner>(
    app: &mut AppContext<R>,
    cert_file: String,
    key_file: String,
    days: i64,
    crl_days: i64,
    serial: Option<i64>,
    crl_serial: Option<i64>,
    ca_url: Option<String>,
    crl_url: Option<String>,
) -> Result<(), OpcaError> {
    output::title("Importing a Certificate Authority from file");

    let cert_pem = std::fs::read(&cert_file)?;
    output::print_result(&format!("Read certificate from {cert_file}"), !cert_pem.is_empty());

    let key_pem = std::fs::read(&key_file)?;
    output::print_result(&format!("Read private key from {key_file}"), !key_pem.is_empty());

    if cert_pem.is_empty() || key_pem.is_empty() {
        return Err(OpcaError::Other("Certificate or key file is empty".into()));
    }

    // Extract serial from cert if not provided
    let next_serial = serial.unwrap_or(1);
    let next_crl_serial = crl_serial.unwrap_or(1);

    let config = CaConfig {
        next_serial: Some(next_serial),
        next_crl_serial: Some(next_crl_serial),
        days: Some(days),
        crl_days: Some(crl_days),
        ca_url,
        crl_url,
        ..CaConfig::default()
    };

    with_lock(app, "ca_import", |app| {
        let op = app.take_op()?;
        let ca = CertificateAuthority::import_ca(op, &cert_pem, Some(&key_pem), &config)?;
        let valid = ca.is_valid().unwrap_or(false);
        output::print_result("CA certificate validation", valid);
        app.ca = Some(ca);
        Ok(())
    })
}

fn handle_export<R: CommandRunner>(
    app: &mut AppContext<R>,
    with_key: bool,
    to_stdout: bool,
    cert_out: Option<String>,
    key_out: Option<String>,
) -> Result<(), OpcaError> {
    let ca = app.ca.as_ref().ok_or(OpcaError::CaNotFound)?;

    let cert_pem = ca.get_certificate()?;
    let key_pem = if with_key {
        Some(ca.get_private_key()?)
    } else {
        None
    };

    // Safety checks
    if with_key && cert_out.is_none() && key_out.is_none() && !to_stdout {
        return Err(OpcaError::Other(
            "Cannot export private key without an explicit destination (--key-out or --to-stdout)"
                .into(),
        ));
    }
    if key_out.is_some() && !with_key {
        return Err(OpcaError::Other(
            "--key-out requires --with-key".into(),
        ));
    }

    // File output
    if let Some(ref path) = cert_out {
        write_file(path, cert_pem.as_bytes(), 0o644)?;
        output::print_result(&format!("Certificate written to {path}"), true);
    }
    if let Some(ref path) = key_out {
        if let Some(ref kp) = key_pem {
            write_file(path, kp.as_bytes(), 0o600)?;
            output::print_result(&format!("Private key written to {path}"), true);
        }
    }

    // Stdout output
    if to_stdout || (cert_out.is_none() && key_out.is_none()) {
        print!("{cert_pem}");
        if let Some(ref kp) = key_pem {
            print!("{kp}");
        }
    }

    Ok(())
}

fn handle_list<R: CommandRunner>(
    app: &mut AppContext<R>,
    expired: bool,
    revoked: bool,
    expiring: bool,
    valid: bool,
    cn: Option<String>,
    serial: Option<String>,
) -> Result<(), OpcaError> {
    let ca = app.ca.as_mut().ok_or(OpcaError::CaNotFound)?;
    let db = ca.ca_database.as_mut()
        .ok_or_else(|| OpcaError::Other("Database not loaded".into()))?;

    db.process_ca_database(None, false)?;

    // Determine mode
    let mode = if expired {
        "expired"
    } else if revoked {
        "revoked"
    } else if expiring {
        "expiring"
    } else if valid {
        "valid"
    } else {
        "all"
    };

    let title = if let Some(ref c) = cn {
        format!("Certificate: {c}")
    } else if let Some(ref s) = serial {
        format!("Certificate: serial {s}")
    } else {
        format!("Certificates ({mode})")
    };
    output::subtitle(&title);

    let certs = db.query_all_certs()?;
    let ext_certs = db.query_all_external_certs(None)?;

    let headers = &["Serial", "CN", "Title", "Type", "Status", "Expiry"];
    let mut rows: Vec<Vec<String>> = Vec::new();

    for cert in &certs {
        let status = cert.status.as_deref().unwrap_or("Unknown");
        let is_expiring = db.certs_expires_soon.contains(&cert.serial);

        let display_status = if status == "Valid" && is_expiring {
            "Expiring"
        } else {
            status
        };

        // Apply filters
        if let Some(ref filter_cn) = cn {
            if cert.cn.as_deref() != Some(filter_cn.as_str()) {
                continue;
            }
        }
        if let Some(ref filter_serial) = serial {
            if cert.serial != *filter_serial {
                continue;
            }
        }

        let include = match mode {
            "expired" => status == "Expired",
            "revoked" => status == "Revoked",
            "expiring" => is_expiring,
            "valid" => status == "Valid",
            _ => true,
        };
        if !include {
            continue;
        }

        rows.push(vec![
            cert.serial.clone(),
            cert.cn.clone().unwrap_or_default(),
            cert.title.clone().unwrap_or_default(),
            cert.cert_type.clone().unwrap_or_default(),
            display_status.to_string(),
            cert.expiry_date.clone().unwrap_or_default(),
        ]);
    }

    // Include external certs (unless filtering by CN/serial)
    if cn.is_none() && serial.is_none() {
        for ext in &ext_certs {
            let status = ext.status.as_deref().unwrap_or("Unknown");
            let is_expiring = db.ext_certs_expires_soon.contains(&ext.serial);

            let display_status = if status == "Valid" && is_expiring {
                "Expiring"
            } else {
                status
            };

            let include = match mode {
                "expired" => status == "Expired",
                "revoked" => false,
                "expiring" => is_expiring,
                "valid" => status == "Valid",
                _ => true,
            };
            if !include {
                continue;
            }

            rows.push(vec![
                ext.serial.clone(),
                ext.cn.clone().unwrap_or_default(),
                format!("EXT_{}", ext.cn.clone().unwrap_or_default()),
                ext.cert_type.clone().unwrap_or_else(|| "external".to_string()),
                display_status.to_string(),
                ext.expiry_date.clone().unwrap_or_default(),
            ]);
        }
    }

    output::print_table(headers, &rows);
    println!();
    println!("  Total: {} certificate(s)", rows.len());

    Ok(())
}

fn handle_upload<R: CommandRunner>(
    app: &mut AppContext<R>,
    stores: Vec<String>,
) -> Result<(), OpcaError> {
    output::title("Uploading CA Certificate");

    let ca = app.ca.as_ref().ok_or(OpcaError::CaNotFound)?;

    if stores.is_empty() {
        ca.upload_ca_cert("")?;
        output::print_result("Upload to default public store", true);
    } else {
        for uri in &stores {
            ca.upload_ca_cert(uri)?;
            output::print_result(&format!("Upload to {uri}"), true);
        }
    }

    Ok(())
}

fn handle_resign<R: CommandRunner>(
    app: &mut AppContext<R>,
    ca_days: i64,
) -> Result<(), OpcaError> {
    output::title("Re-signing the CA Certificate");

    with_lock(app, "ca_resign", |app| {
        let ca = app.ca.as_mut().ok_or(OpcaError::CaNotFound)?;
        ca.re_sign_ca(ca_days)?;
        output::print_result("CA certificate re-signed", true);

        let expiry = ca
            .ca_bundle
            .as_ref()
            .and_then(|b| b.get_certificate_attrib("not_after").ok().flatten())
            .unwrap_or_else(|| "Unknown".to_string());
        output::info("New Expiry", &expiry);

        Ok(())
    })
}

/// Print a warning if the CA certificate is approaching expiry.
pub fn warn_ca_expiry<R: CommandRunner>(app: &AppContext<R>) {
    if let Some(ref ca) = app.ca {
        match ca.check_ca_expiry() {
            CaExpiryWarning::Critical { days_remaining } => {
                output::warning(&format!(
                    "CRITICAL: CA certificate expires in {days_remaining} days!"
                ));
            }
            CaExpiryWarning::Prominent { days_remaining } => {
                output::warning(&format!(
                    "CA certificate expires in {days_remaining} days"
                ));
            }
            CaExpiryWarning::CertLifetimeExceedsCa {
                days_remaining,
                cert_lifetime_days,
            } => {
                output::warning(&format!(
                    "CA has {days_remaining} days remaining but default cert lifetime is \
                     {cert_lifetime_days} days — new certificates will outlive the CA"
                ));
            }
            CaExpiryWarning::None => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn write_file(path: &str, data: &[u8], mode: u32) -> Result<(), OpcaError> {
    use std::io::Write;

    if std::path::Path::new(path).exists() {
        return Err(OpcaError::Io(format!("File already exists: {path}")));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)?;
        f.write_all(data)?;
    }

    #[cfg(not(unix))]
    {
        let _ = mode;
        std::fs::write(path, data)?;
    }

    Ok(())
}
