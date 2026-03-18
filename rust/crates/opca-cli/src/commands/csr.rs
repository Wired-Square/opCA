use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::{X509Req, X509};

use opca_core::constants::DEFAULT_OP_CONF;
use opca_core::error::OpcaError;
use opca_core::op::{CommandRunner, ShellRunner, StoreAction};
use opca_core::services::cert::{CertBundleConfig, CertificateBundle, CertType};
use opca_core::services::database::CsrRecord;
use opca_core::utils::datetime::{self, DateTimeFormat};

use crate::app::AppContext;
use crate::output;
use crate::{CsrAction, CsrArgs};

pub fn dispatch(args: CsrArgs, app: &mut AppContext<ShellRunner>) -> Result<(), OpcaError> {
    match args.action {
        CsrAction::Create {
            csr_type,
            cn,
            email,
            country,
        } => handle_create(app, csr_type, cn, email, country),
        CsrAction::Import { cn, cert_file } => handle_import(app, cn, cert_file),
        CsrAction::Sign {
            csr_file,
            csr_pem,
            csr_type,
            cn,
        } => handle_sign(app, csr_file, csr_pem, csr_type, cn),
    }
}

fn handle_create<R: CommandRunner>(
    app: &mut AppContext<R>,
    csr_type: String,
    cn: String,
    email: String,
    country: Option<String>,
) -> Result<(), OpcaError> {
    output::title("Creating Certificate Signing Request");

    let cert_type: CertType = csr_type.parse()?;
    let op_title = format!("CSR_{cn}");

    let op = app.op()?;
    if op.item_exists(&op_title) {
        return Err(OpcaError::Other(format!(
            "Item '{op_title}' already exists in 1Password"
        )));
    }

    // Resolve country from args or CA config
    let resolved_country = if let Some(c) = country {
        Some(c)
    } else if let Some(ref ca) = app.ca {
        if let Some(ref db) = ca.ca_database {
            db.get_config().ok().and_then(|c| c.country)
        } else {
            None
        }
    } else {
        None
    };

    let config = CertBundleConfig {
        cn: Some(cn.clone()),
        email: Some(email.clone()),
        country: resolved_country,
        ..CertBundleConfig::default()
    };

    let bundle = CertificateBundle::generate(cert_type.clone(), &cn, config)?;
    let key_pem = bundle.private_key_pem()?;
    let csr_pem = bundle
        .csr_pem()
        .ok_or_else(|| OpcaError::Other("CSR not generated".into()))?;

    // Store in 1Password
    let attributes = vec![
        format!("{}={}", DEFAULT_OP_CONF.cert_type_item, cert_type),
        format!("{}={}", DEFAULT_OP_CONF.cn_item, cn),
        format!("{}={}", DEFAULT_OP_CONF.key_item, key_pem),
        format!("{}={}", DEFAULT_OP_CONF.csr_item, csr_pem),
    ];
    let attr_refs: Vec<&str> = attributes.iter().map(|s| s.as_str()).collect();

    let op = app.op()?;
    op.store_item(
        &op_title,
        Some(&attr_refs),
        StoreAction::Create,
        DEFAULT_OP_CONF.category,
        None,
        None,
    )?;

    output::print_result(&format!("CSR '{op_title}' stored"), true);

    // Record in database if CA is available
    if let Some(ref mut ca) = app.ca {
        if let Some(ref db) = ca.ca_database {
            let subject = bundle
                .csr
                .as_ref()
                .map(|c| csr_subject_string(c))
                .unwrap_or_default();

            let record = CsrRecord {
                id: None,
                cn: Some(cn.clone()),
                title: Some(op_title),
                csr_type: Some(cert_type.to_string()),
                email: Some(email),
                subject: Some(subject),
                status: Some("Pending".to_string()),
                created_date: Some(datetime::now_utc_str(DateTimeFormat::Compact)),
                csr_pem: Some(csr_pem.clone()),
            };
            let _ = db.add_csr(&record);
        }
        let _ = ca.store_ca_database();
    }

    // Print CSR PEM to stdout
    println!();
    print!("{csr_pem}");

    Ok(())
}

fn handle_import<R: CommandRunner>(
    app: &mut AppContext<R>,
    cn_override: Option<String>,
    cert_file: String,
) -> Result<(), OpcaError> {
    output::title("Importing Certificate into CSR Entry");

    let cert_pem_bytes = std::fs::read(&cert_file)?;
    let cert = X509::from_pem(&cert_pem_bytes)
        .or_else(|_| X509::from_der(&cert_pem_bytes))
        .map_err(|e| OpcaError::InvalidCertificate(format!("Failed to parse certificate: {e}")))?;

    let cn = cn_override
        .or_else(|| cert_cn(&cert))
        .ok_or_else(|| OpcaError::Other("No CN found in certificate and no --cn provided".into()))?;

    let csr_title = format!("CSR_{cn}");

    // Ensure CA is loaded for this operation
    app.ensure_ca()?;

    let ca = app.ca.as_mut().ok_or(OpcaError::CaNotFound)?;

    // Retrieve CSR item from 1Password
    let item_json = ca
        .op
        .get_item(&csr_title, "json")
        .map_err(|e| OpcaError::Other(format!("No existing entry '{csr_title}' found: {e}")))?;

    let obj: serde_json::Value = serde_json::from_str(&item_json)
        .map_err(|e| OpcaError::Other(format!("Failed to parse 1Password item: {e}")))?;

    let fields = obj
        .get("fields")
        .and_then(|f| f.as_array())
        .ok_or_else(|| OpcaError::Other("No fields in 1Password item".into()))?;

    let mut key_pem_str: Option<String> = None;
    let mut csr_pem_str: Option<String> = None;

    for field in fields {
        let label = field.get("label").and_then(|v| v.as_str()).unwrap_or("");
        let value = field.get("value").and_then(|v| v.as_str()).unwrap_or("");
        if value.is_empty() {
            continue;
        }
        match label {
            "private_key" => key_pem_str = Some(value.to_string()),
            "certificate_signing_request" => csr_pem_str = Some(value.to_string()),
            _ => {}
        }
    }

    let key_pem = key_pem_str.ok_or_else(|| OpcaError::Other("No private key found in CSR item".into()))?;

    // Validate certificate public key matches private key
    let private_key = PKey::private_key_from_pem(key_pem.as_bytes())
        .map_err(|e| OpcaError::Crypto(format!("Failed to parse private key: {e}")))?;

    let cert_pub_der = cert
        .public_key()
        .map_err(|e| OpcaError::Crypto(format!("Get certificate public key: {e}")))?
        .public_key_to_der()
        .map_err(|e| OpcaError::Crypto(format!("Encode certificate public key: {e}")))?;
    let key_pub_der = private_key
        .public_key_to_der()
        .map_err(|e| OpcaError::Crypto(format!("Encode private key public key: {e}")))?;

    if cert_pub_der != key_pub_der {
        return Err(OpcaError::InvalidCertificate(
            "Certificate public key does not match the private key from the CSR".into(),
        ));
    }

    // Delete old CSR item
    ca.op.delete_item(&csr_title, true)?;

    // Build certificate bundle
    let bundle = CertificateBundle::import(
        CertType::External,
        &cn,
        &cert_pem_bytes,
        Some(key_pem.as_bytes()),
        csr_pem_str.as_deref().map(|s| s.as_bytes()),
        None,
        CertBundleConfig::default(),
    )?;

    // Extract issuer info
    let issuer = cert_issuer_cn(&cert).unwrap_or_else(|| "Unknown".to_string());
    let issuer_subject = cert_issuer_subject(&cert);

    // Store as external certificate
    ca.store_certbundle_for(&bundle, Some(&issuer), Some(&issuer_subject), false)?;

    // Update CSR status
    if let Some(ref db) = ca.ca_database {
        let _ = db.update_csr(&CsrRecord {
            cn: Some(cn.clone()),
            status: Some("Complete".to_string()),
            ..CsrRecord::default()
        });
    }
    ca.store_ca_database()?;

    output::print_result(&format!("Imported certificate for '{cn}'"), true);
    Ok(())
}

fn handle_sign<R: CommandRunner>(
    app: &mut AppContext<R>,
    csr_file: Option<String>,
    csr_pem_arg: Option<String>,
    csr_type: String,
    cn_override: Option<String>,
) -> Result<(), OpcaError> {
    output::title("Signing Certificate Signing Request");

    let cert_type: CertType = csr_type.parse()?;

    // Read CSR
    let csr_pem_bytes = if let Some(ref file) = csr_file {
        std::fs::read(file)?
    } else if let Some(ref pem) = csr_pem_arg {
        pem.as_bytes().to_vec()
    } else {
        return Err(OpcaError::Other("Either --csr-file or --csr-pem is required".into()));
    };

    let csr = X509Req::from_pem(&csr_pem_bytes)
        .or_else(|_| X509Req::from_der(&csr_pem_bytes))
        .map_err(|e| OpcaError::Crypto(format!("Failed to parse CSR: {e}")))?;

    let cn = cn_override
        .or_else(|| csr_cn(&csr))
        .ok_or_else(|| OpcaError::Other("CSR has no CN and no --cn override provided".into()))?;

    // Ensure CA is loaded
    app.ensure_ca()?;
    let ca = app.ca.as_mut().ok_or(OpcaError::CaNotFound)?;

    // Sign CSR with CA
    let signed_cert = ca.sign_certificate(&csr, &cert_type)?;
    let cert_pem_bytes = signed_cert
        .to_pem()
        .map_err(|e| OpcaError::Crypto(format!("Encode signed certificate: {e}")))?;
    let cert_pem = String::from_utf8_lossy(&cert_pem_bytes).to_string();

    // Build a CertificateBundle with cert + CSR
    let bundle = CertificateBundle::import(
        cert_type,
        &cn,
        &cert_pem_bytes,
        None,
        Some(&csr_pem_bytes),
        None,
        CertBundleConfig::default(),
    )?;

    // Store in 1Password
    ca.store_certbundle_for(&bundle, None, None, true)?;

    output::print_result(&format!("Signed certificate for '{cn}'"), true);
    println!();
    print!("{cert_pem}");

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn csr_subject_string(csr: &X509Req) -> String {
    csr.subject_name()
        .entries()
        .filter_map(|e| {
            let sn = e.object().nid().short_name().unwrap_or("??");
            e.data().as_utf8().ok().map(|v| format!("{sn}={v}"))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn csr_cn(csr: &X509Req) -> Option<String> {
    csr.subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
}

fn cert_cn(cert: &X509) -> Option<String> {
    cert.subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
}

fn cert_issuer_cn(cert: &X509) -> Option<String> {
    cert.issuer_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
}

fn cert_issuer_subject(cert: &X509) -> String {
    cert.issuer_name()
        .entries()
        .filter_map(|e| {
            let sn = e.object().nid().short_name().unwrap_or("??");
            e.data().as_utf8().ok().map(|v| format!("{sn}={v}"))
        })
        .collect::<Vec<_>>()
        .join(", ")
}
