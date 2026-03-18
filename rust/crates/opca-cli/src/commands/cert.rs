use opca_core::error::OpcaError;
use opca_core::op::{CommandRunner, ShellRunner};
use opca_core::services::cert::{CertBundleConfig, CertType};
use opca_core::services::database::CertLookup;

use crate::app::{with_lock, AppContext};
use crate::output;
use crate::{CertAction, CertArgs, CertCreateArgs, CertExportArgs, CertIdentifier, CertRevokeArgs};

pub fn dispatch(args: CertArgs, app: &mut AppContext<ShellRunner>) -> Result<(), OpcaError> {
    match args.action {
        CertAction::Create(create_args) => handle_create(app, create_args),
        CertAction::Export(export_args) => handle_export(app, export_args),
        CertAction::Info(id) => handle_info(app, id),
        CertAction::Import {
            cert_file,
            key_file,
            cn,
            external: _,
        } => handle_import(app, cert_file, key_file, cn),
        CertAction::Rekey(id) => handle_rekey(app, id),
        CertAction::Renew(id) => handle_renew(app, id),
        CertAction::Revoke(revoke_args) => handle_revoke(app, revoke_args),
    }
}

fn handle_create<R: CommandRunner>(
    app: &mut AppContext<R>,
    args: CertCreateArgs,
) -> Result<(), OpcaError> {
    output::title("Creating Certificate");

    let cert_type: CertType = args.cert_type.parse()?;

    // Build list of CNs to create
    let cn_list: Vec<(String, Vec<String>)> = if let Some(file) = args.file {
        parse_bulk_file(&file)?
    } else if let Some(cn) = args.cn {
        vec![(cn, args.alt)]
    } else {
        return Err(OpcaError::Other("Either --cn or --file is required".into()));
    };

    with_lock(app, "cert_create", |app| {
        for (cn, alt_names) in &cn_list {
            let ca = app.ca.as_mut().ok_or(OpcaError::CaNotFound)?;

            // Check if already exists
            if ca.op.item_exists(cn) {
                output::warning(&format!("'{cn}' already exists, skipping"));
                continue;
            }

            let db = ca.ca_database.as_ref()
                .ok_or_else(|| OpcaError::Other("Database not loaded".into()))?;
            let ca_config = db.get_config()?;

            let config = CertBundleConfig {
                cn: Some(cn.clone()),
                key_size: args.serial.map(|_| 0).or(None), // use default
                org: ca_config.org,
                ou: ca_config.ou,
                email: ca_config.email,
                city: ca_config.city,
                state: ca_config.state,
                country: ca_config.country,
                alt_dns_names: if alt_names.is_empty() {
                    None
                } else {
                    Some(alt_names.clone())
                },
                next_serial: ca_config.next_serial,
                ca_days: ca_config.days,
            };

            let (bundle, issuance_warning) = ca.generate_certificate_bundle(cert_type.clone(), cn, config)?;
            let valid = bundle.is_valid().unwrap_or(false);
            output::print_result(&format!("Certificate '{cn}'"), valid);
            if let Some(ref w) = issuance_warning {
                output::warning(&w.message);
            }
        }
        Ok(())
    })
}

fn handle_export<R: CommandRunner>(
    app: &mut AppContext<R>,
    args: CertExportArgs,
) -> Result<(), OpcaError> {
    let cn = resolve_cn(app, args.cn.as_deref(), args.serial.as_deref())?;

    let ca = app.ca.as_ref().ok_or(OpcaError::CaNotFound)?;
    let bundle = ca
        .retrieve_certbundle(&cn)?
        .ok_or_else(|| OpcaError::CertificateNotFound(cn.clone()))?;

    if args.format == "pkcs12" {
        let password = get_password("Enter export password: ")?;
        let pkcs12_data = bundle.export_pkcs12(Some(&password), Some(&cn), None)?;

        if args.to_stdout {
            use base64::Engine;
            let encoded = base64::engine::general_purpose::STANDARD.encode(&pkcs12_data);
            println!("{encoded}");
        } else if let Some(ref path) = args.outfile {
            super::ca::write_file(path, &pkcs12_data, 0o600)?;
            output::print_result(&format!("PKCS#12 written to {path}"), true);
        } else {
            return Err(OpcaError::Other(
                "PKCS#12 export requires --outfile or --to-stdout".into(),
            ));
        }
    } else {
        // PEM format
        let cert_pem = bundle.certificate_pem()?;
        let key_pem = if args.with_key {
            Some(bundle.private_key_pem()?)
        } else {
            None
        };

        if args.with_key && args.cert_out.is_none() && args.key_out.is_none() && !args.to_stdout {
            return Err(OpcaError::Other(
                "Cannot export private key without an explicit destination".into(),
            ));
        }

        if let Some(ref path) = args.cert_out {
            super::ca::write_file(path, cert_pem.as_bytes(), 0o644)?;
            output::print_result(&format!("Certificate written to {path}"), true);
        }
        if let Some(ref path) = args.key_out {
            if let Some(ref kp) = key_pem {
                super::ca::write_file(path, kp.as_bytes(), 0o600)?;
                output::print_result(&format!("Private key written to {path}"), true);
            }
        }

        if args.to_stdout || (args.cert_out.is_none() && args.key_out.is_none()) {
            print!("{cert_pem}");
            if let Some(ref kp) = key_pem {
                print!("{kp}");
            }
        }
    }

    Ok(())
}

fn handle_info<R: CommandRunner>(
    app: &mut AppContext<R>,
    id: CertIdentifier,
) -> Result<(), OpcaError> {
    let cn = resolve_cn(app, id.cn.as_deref(), id.serial.as_deref())?;

    let ca = app.ca.as_ref().ok_or(OpcaError::CaNotFound)?;
    let bundle = ca
        .retrieve_certbundle(&cn)?
        .ok_or_else(|| OpcaError::CertificateNotFound(cn.clone()))?;

    output::subtitle(&format!("Certificate: {cn}"));

    let attr = |name: &str| -> String {
        bundle
            .get_certificate_attrib(name)
            .ok()
            .flatten()
            .unwrap_or_else(|| "N/A".to_string())
    };

    output::info("Type", &bundle.cert_type.to_string());
    output::info("Subject", &attr("subject"));
    output::info("Issuer", &attr("issuer"));
    output::info("Serial", &attr("serial"));
    output::info("Not Before", &attr("not_before"));
    output::info("Not After", &attr("not_after"));
    output::info("Key Type", &attr("key_type"));
    output::info("Key Size", &attr("key_size"));

    let san = attr("san");
    if san != "N/A" {
        output::info("SAN", &san);
    }

    let valid = bundle.is_valid().unwrap_or(false);
    output::info("Valid", if valid { "Yes" } else { "No" });

    // Print PEM
    if let Ok(pem) = bundle.certificate_pem() {
        println!();
        print!("{pem}");
    }

    Ok(())
}

fn handle_import<R: CommandRunner>(
    app: &mut AppContext<R>,
    cert_file: String,
    key_file: Option<String>,
    cn: Option<String>,
) -> Result<(), OpcaError> {
    output::title("Importing Certificate");

    let cert_pem = std::fs::read(&cert_file)?;
    let key_pem = key_file
        .as_ref()
        .map(|f| std::fs::read(f))
        .transpose()?;

    with_lock(app, "cert_import", |app| {
        let ca = app.ca.as_mut().ok_or(OpcaError::CaNotFound)?;
        let bundle = ca.import_certificate_bundle(
            &cert_pem,
            key_pem.as_deref(),
            None,
            None,
            cn.as_deref(),
        )?;

        let imported_cn = bundle
            .get_certificate_attrib("cn")
            .ok()
            .flatten()
            .unwrap_or_else(|| "Unknown".to_string());
        output::print_result(&format!("Import certificate '{imported_cn}'"), true);
        Ok(())
    })
}

fn handle_rekey<R: CommandRunner>(
    app: &mut AppContext<R>,
    id: CertIdentifier,
) -> Result<(), OpcaError> {
    output::title("Rekeying Certificate");

    let lookup = make_lookup(id.cn.as_deref(), id.serial.as_deref())?;

    with_lock(app, "cert_rekey", |app| {
        let ca = app.ca.as_mut().ok_or(OpcaError::CaNotFound)?;
        let (new_pem, issuance_warning) = ca.rekey_certificate_bundle(&lookup)?;
        output::print_result("Certificate rekeyed", true);
        if let Some(ref w) = issuance_warning {
            output::warning(&w.message);
        }
        print!("{new_pem}");
        Ok(())
    })
}

fn handle_renew<R: CommandRunner>(
    app: &mut AppContext<R>,
    id: CertIdentifier,
) -> Result<(), OpcaError> {
    output::title("Renewing Certificate");

    let lookup = make_lookup(id.cn.as_deref(), id.serial.as_deref())?;

    with_lock(app, "cert_renew", |app| {
        let ca = app.ca.as_mut().ok_or(OpcaError::CaNotFound)?;
        let (new_pem, issuance_warning) = ca.renew_certificate_bundle(&lookup)?;
        output::print_result("Certificate renewed", true);
        if let Some(ref w) = issuance_warning {
            output::warning(&w.message);
        }
        print!("{new_pem}");
        Ok(())
    })
}

fn handle_revoke<R: CommandRunner>(
    app: &mut AppContext<R>,
    args: CertRevokeArgs,
) -> Result<(), OpcaError> {
    output::title("Revoking Certificate(s)");

    // Collect lookups
    let mut lookups: Vec<CertLookup> = Vec::new();

    if let Some(serial) = args.serial {
        lookups.push(CertLookup::Serial(serial));
    }
    if let Some(cn) = args.cn {
        lookups.push(CertLookup::Cn(cn));
    }
    if let Some(file) = args.file {
        for (cn, _) in parse_bulk_file(&file)? {
            lookups.push(CertLookup::Cn(cn));
        }
    }

    if lookups.is_empty() {
        return Err(OpcaError::Other(
            "At least one of --cn, --serial, or --file is required".into(),
        ));
    }

    let mut any_revoked = false;

    with_lock(app, "cert_revoke", |app| {
        for lookup in &lookups {
            let ca = app.ca.as_mut().ok_or(OpcaError::CaNotFound)?;
            let label = format!("{lookup:?}");
            match ca.revoke_certificate(lookup) {
                Ok(true) => {
                    output::print_result(&format!("Revoke {label}"), true);
                    any_revoked = true;
                }
                Ok(false) => {
                    output::print_result(&format!("Revoke {label}"), false);
                }
                Err(e) => {
                    output::warning(&format!("Revoke {label}: {e}"));
                }
            }
        }

        // Regenerate CRL if any were revoked
        if any_revoked {
            let ca = app.ca.as_mut().ok_or(OpcaError::CaNotFound)?;
            let crl_pem = ca.generate_crl()?;
            output::print_result("CRL regenerated", true);
            print!("{crl_pem}");
        }

        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn resolve_cn<R: CommandRunner>(
    app: &AppContext<R>,
    cn: Option<&str>,
    serial: Option<&str>,
) -> Result<String, OpcaError> {
    if let Some(cn) = cn {
        return Ok(cn.to_string());
    }
    if let Some(serial) = serial {
        // Look up title from database
        let ca = app.ca.as_ref().ok_or(OpcaError::CaNotFound)?;
        let db = ca.ca_database.as_ref()
            .ok_or_else(|| OpcaError::Other("Database not loaded".into()))?;
        let record = db
            .query_cert(&CertLookup::Serial(serial.to_string()), false)?
            .ok_or_else(|| OpcaError::CertificateNotFound(serial.to_string()))?;
        return Ok(record.title.unwrap_or_else(|| serial.to_string()));
    }
    Err(OpcaError::Other("Either --cn or --serial is required".into()))
}

fn make_lookup(cn: Option<&str>, serial: Option<&str>) -> Result<CertLookup, OpcaError> {
    if let Some(cn) = cn {
        return Ok(CertLookup::Cn(cn.to_string()));
    }
    if let Some(serial) = serial {
        return Ok(CertLookup::Serial(serial.to_string()));
    }
    Err(OpcaError::Other("Either --cn or --serial is required".into()))
}

/// Parse a bulk file: one CN per line, # comments, blank lines ignored.
fn parse_bulk_file(path: &str) -> Result<Vec<(String, Vec<String>)>, OpcaError> {
    let content = std::fs::read_to_string(path)?;
    let mut result = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Format: CN [--alt ALT1 --alt ALT2 ...]
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        let cn = parts[0].to_string();
        let mut alts = Vec::new();
        let mut i = 1;
        while i < parts.len() {
            if parts[i] == "--alt" && i + 1 < parts.len() {
                alts.push(parts[i + 1].to_string());
                i += 2;
            } else {
                i += 1;
            }
        }
        result.push((cn, alts));
    }
    Ok(result)
}

pub fn get_password(prompt: &str) -> Result<String, OpcaError> {
    let password = rpassword::prompt_password_stderr(prompt)
        .map_err(|e| OpcaError::Other(format!("Failed to read password: {e}")))?;
    let confirm = rpassword::prompt_password_stderr("Confirm password: ")
        .map_err(|e| OpcaError::Other(format!("Failed to read password: {e}")))?;
    if password != confirm {
        return Err(OpcaError::Other("Passwords do not match".into()));
    }
    Ok(password)
}

pub fn get_password_single(prompt: &str) -> Result<String, OpcaError> {
    rpassword::prompt_password_stderr(prompt)
        .map_err(|e| OpcaError::Other(format!("Failed to read password: {e}")))
}

