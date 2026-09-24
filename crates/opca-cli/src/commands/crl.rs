use opca_core::error::OpcaError;
use opca_core::op::{CommandRunner, ShellRunner};
use opca_core::services::ca::parse_crl_metadata;

use crate::app::{with_lock, AppContext};
use crate::output;
use crate::{CrlAction, CrlArgs};

pub fn dispatch(args: CrlArgs, app: &mut AppContext<ShellRunner>) -> Result<(), OpcaError> {
    match args.action {
        CrlAction::Create => handle_create(app),
        CrlAction::Export {
            format,
            to_stdout,
            outfile,
        } => handle_export(app, format, to_stdout, outfile),
        CrlAction::Info => handle_info(app),
        CrlAction::Upload { generate, store } => handle_upload(app, generate, store),
    }
}

fn handle_create<R: CommandRunner>(app: &mut AppContext<R>) -> Result<(), OpcaError> {
    output::title("Generating Certificate Revocation List");

    with_lock(app, "crl_create", |app| {
        let ca = app.ca.as_mut().ok_or(OpcaError::CaNotFound)?;
        let crl_pem = ca.generate_crl()?;
        output::print_result("CRL generation", true);
        print!("{crl_pem}");
        Ok(())
    })
}

fn handle_export<R: CommandRunner>(
    app: &mut AppContext<R>,
    format: String,
    _to_stdout: bool,
    outfile: Option<String>,
) -> Result<(), OpcaError> {
    let ca = app.ca.as_mut().ok_or(OpcaError::CaNotFound)?;
    let crl_pem = ca
        .get_crl()?
        .ok_or_else(|| OpcaError::Other("CRL not found".into()))?;

    let data = if format == "der" {
        use openssl::x509::X509Crl;
        let crl = X509Crl::from_pem(crl_pem.as_bytes())
            .map_err(|e| OpcaError::Crypto(format!("Parse CRL: {e}")))?;
        crl.to_der()
            .map_err(|e| OpcaError::Crypto(format!("CRL to DER: {e}")))?
    } else {
        crl_pem.into_bytes()
    };

    if let Some(ref path) = outfile {
        super::ca::write_file(path, &data, 0o644)?;
        output::print_result(&format!("CRL written to {path}"), true);
    } else {
        // stdout
        output::write_stdout(&data)
            .map_err(|e| OpcaError::Io(e.to_string()))?;
    }

    Ok(())
}

fn handle_info<R: CommandRunner>(app: &mut AppContext<R>) -> Result<(), OpcaError> {
    let ca = app.ca.as_mut().ok_or(OpcaError::CaNotFound)?;
    let crl_pem = ca
        .get_crl()?
        .ok_or_else(|| OpcaError::Other("CRL not found".into()))?;

    let metadata = parse_crl_metadata(&crl_pem)?;

    output::subtitle("Certificate Revocation List");
    output::info("CRL Number", &metadata.crl_number.map(|n| n.to_string()).unwrap_or_else(|| "N/A".to_string()));
    output::info("Issuer", metadata.issuer.as_deref().unwrap_or("N/A"));
    output::info("Last Update", metadata.last_update.as_deref().unwrap_or("N/A"));
    output::info("Next Update", metadata.next_update.as_deref().unwrap_or("N/A"));
    output::info(
        "Revoked Certificates",
        &metadata.revoked_count.map(|n| n.to_string()).unwrap_or_else(|| "0".to_string()),
    );

    // Parse revoked entries from JSON if available
    if let Some(ref json) = metadata.revoked_json {
        if let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(json) {
            if !entries.is_empty() {
                println!();
                let headers = &["Serial", "Revocation Date"];
                let rows: Vec<Vec<String>> = entries
                    .iter()
                    .map(|e| {
                        vec![
                            e["serial"].as_str().unwrap_or("?").to_string(),
                            e["date"].as_str().unwrap_or("?").to_string(),
                        ]
                    })
                    .collect();
                output::print_table(headers, &rows);
            }
        }
    }

    Ok(())
}

fn handle_upload<R: CommandRunner>(
    app: &mut AppContext<R>,
    generate: bool,
    stores: Vec<String>,
) -> Result<(), OpcaError> {
    output::title("Uploading Certificate Revocation List");

    let ca = app.ca.as_mut().ok_or(OpcaError::CaNotFound)?;

    if generate {
        ca.generate_crl()?;
        output::print_result("CRL generated", true);
    }

    if stores.is_empty() {
        ca.upload_crl("")?;
        output::print_result("Upload to default public store", true);
    } else {
        for uri in &stores {
            ca.upload_crl(uri)?;
            output::print_result(&format!("Upload to {uri}"), true);
        }
    }

    Ok(())
}
