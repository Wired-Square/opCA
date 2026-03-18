use tauri::State;

use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::{X509Req, X509};

use opca_core::constants::DEFAULT_OP_CONF;
use opca_core::op::StoreAction;
use opca_core::services::cert::{CertBundleConfig, CertificateBundle, CertType};
use opca_core::services::database::{CsrLookup, CsrRecord};
use opca_core::utils::datetime::{now_utc_str, DateTimeFormat};

use crate::commands::dto::{
    CertListItem, CreateCsrRequest, CreateCsrResult, CsrListItem, DecodeCsrResult,
    ImportCsrCertRequest, SignCsrRequest, SignCsrResult,
};
use crate::state::AppState;

fn record_to_list_item(r: &CsrRecord) -> CsrListItem {
    CsrListItem {
        id: r.id,
        cn: r.cn.clone(),
        title: r.title.clone(),
        csr_type: r.csr_type.clone(),
        email: r.email.clone(),
        subject: r.subject.clone(),
        status: r.status.clone(),
        created_date: r.created_date.clone(),
    }
}

/// Extract subject as a human-readable string from an X509Req.
fn csr_subject_string(csr: &X509Req) -> String {
    csr.subject_name()
        .entries()
        .filter_map(|e| {
            let nid = e.object().nid();
            let sn = nid.short_name().unwrap_or("??");
            e.data().as_utf8().ok().map(|v| format!("{sn}={v}"))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Extract CN from an X509Req subject.
fn csr_cn(csr: &X509Req) -> Option<String> {
    csr.subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
}

/// Extract CN from an X509 certificate subject.
fn cert_cn(cert: &X509) -> Option<String> {
    cert.subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
}

/// Extract issuer CN from an X509 certificate.
fn cert_issuer_cn(cert: &X509) -> Option<String> {
    cert.issuer_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
}

/// Extract issuer subject as a human-readable string from an X509 certificate.
fn cert_issuer_subject(cert: &X509) -> String {
    cert.issuer_name()
        .entries()
        .filter_map(|e| {
            let nid = e.object().nid();
            let sn = nid.short_name().unwrap_or("??");
            e.data().as_utf8().ok().map(|v| format!("{sn}={v}"))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Extract Subject Alternative Names (DNS entries) from a CSR.
fn csr_sans(csr: &X509Req) -> Vec<String> {
    let cn = csr_cn(csr);
    let csr_text = csr
        .to_text()
        .map(|v| String::from_utf8_lossy(&v).to_string())
        .unwrap_or_default();

    let mut sans = Vec::new();
    for line in csr_text.lines() {
        let trimmed = line.trim();
        if trimmed.contains("DNS:") && !trimmed.starts_with("X509v3") {
            for part in trimmed.split(',') {
                let part = part.trim();
                if let Some(dns) = part.strip_prefix("DNS:") {
                    if cn.as_deref() != Some(dns) && !sans.contains(&dns.to_string()) {
                        sans.push(dns.to_string());
                    }
                }
            }
        }
    }
    sans
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn decode_csr(csr_pem: String) -> Result<DecodeCsrResult, String> {
    let csr = X509Req::from_pem(csr_pem.as_bytes())
        .map_err(|e| format!("Failed to parse CSR PEM: {e}"))?;

    Ok(DecodeCsrResult {
        cn: csr_cn(&csr),
        subject: csr_subject_string(&csr),
        alt_dns_names: csr_sans(&csr),
    })
}

#[tauri::command]
pub async fn list_csrs(
    state: State<'_, AppState>,
    status: Option<String>,
) -> Result<Vec<CsrListItem>, String> {
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    let db = ca
        .ca_database
        .as_ref()
        .ok_or("Database not loaded")?;

    let records = db
        .query_all_csrs(status.as_deref())
        .map_err(|e| e.to_string())?;

    Ok(records.iter().map(record_to_list_item).collect())
}

#[tauri::command]
pub async fn get_csr_info(
    state: State<'_, AppState>,
    cn: String,
) -> Result<CreateCsrResult, String> {
    let conn = state.ensure_ca()?;
    let ca = conn.ca.as_ref().ok_or("CA not available")?;

    let db = ca
        .ca_database
        .as_ref()
        .ok_or("Database not loaded")?;

    let record = db
        .query_csr(&CsrLookup::Cn(cn))
        .map_err(|e| e.to_string())?
        .ok_or("CSR not found")?;

    let csr_pem = record.csr_pem.clone().unwrap_or_default();
    Ok(CreateCsrResult {
        item: record_to_list_item(&record),
        csr_pem,
    })
}

#[tauri::command]
pub async fn create_csr(
    state: State<'_, AppState>,
    request: CreateCsrRequest,
) -> Result<CreateCsrResult, String> {
    let cert_type: CertType = request
        .csr_type
        .parse()
        .map_err(|e: opca_core::error::OpcaError| e.to_string())?;

    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    let db = ca
        .ca_database
        .as_ref()
        .ok_or("Database not loaded")?;
    let ca_config = db.get_config().map_err(|e| e.to_string())?;

    // Check for duplicate
    let op_title = format!("CSR_{}", request.cn);
    if ca.op.item_exists(&op_title) {
        return Err(format!("Item '{}' already exists in 1Password", op_title));
    }

    // Resolve country from request or CA config
    let country = request.country.or(ca_config.country);

    let bundle_config = CertBundleConfig {
        cn: Some(request.cn.clone()),
        key_size: request.key_size,
        org: ca_config.org,
        ou: ca_config.ou,
        email: request.email.clone().or(ca_config.email),
        city: ca_config.city,
        state: ca_config.state,
        country,
        alt_dns_names: request.alt_dns_names.clone(),
        next_serial: ca_config.next_serial,
        ca_days: ca_config.days,
    };

    // Generate key + CSR (no certificate)
    let bundle = CertificateBundle::generate(cert_type.clone(), &request.cn, bundle_config)
        .map_err(|e| {
            state.log_err("create_csr", Some(e.to_string()));
            e.to_string()
        })?;

    let key_pem = bundle.private_key_pem().map_err(|e| e.to_string())?;
    let csr_pem = bundle.csr_pem().ok_or("CSR not generated")?;

    // Store private key + CSR in 1Password (no certificate)
    let attributes = vec![
        format!("{}={}", DEFAULT_OP_CONF.cert_type_item, cert_type),
        format!("{}={}", DEFAULT_OP_CONF.cn_item, request.cn),
        format!("{}={}", DEFAULT_OP_CONF.key_item, key_pem),
        format!("{}={}", DEFAULT_OP_CONF.csr_item, csr_pem),
    ];
    let attr_refs: Vec<&str> = attributes.iter().map(|s| s.as_str()).collect();

    ca.op
        .store_item(
            &op_title,
            Some(&attr_refs),
            StoreAction::Create,
            DEFAULT_OP_CONF.category,
            None,
            None,
        )
        .map_err(|e| {
            state.log_err("create_csr", Some(e.to_string()));
            e.to_string()
        })?;

    // Extract subject from CSR
    let subject = bundle
        .csr
        .as_ref()
        .map(|c| csr_subject_string(c))
        .unwrap_or_default();

    // Record in database
    let record = CsrRecord {
        id: None,
        cn: Some(request.cn.clone()),
        title: Some(op_title),
        csr_type: Some(cert_type.to_string()),
        email: request.email,
        subject: Some(subject),
        status: Some("Pending".to_string()),
        created_date: Some(now_utc_str(DateTimeFormat::Compact)),
        csr_pem: Some(csr_pem.clone()),
    };

    let db = ca
        .ca_database
        .as_ref()
        .ok_or("Database not loaded")?;
    db.add_csr(&record).map_err(|e| e.to_string())?;

    ca.store_ca_database().map_err(|e| {
        state.log_err("create_csr", Some(e.to_string()));
        e.to_string()
    })?;

    state.log_ok(
        "create_csr",
        Some(format!("Created {} CSR '{}'", cert_type, request.cn)),
    );

    Ok(CreateCsrResult {
        item: record_to_list_item(&record),
        csr_pem,
    })
}

#[tauri::command]
pub async fn sign_csr(
    state: State<'_, AppState>,
    request: SignCsrRequest,
) -> Result<SignCsrResult, String> {
    let cert_type: CertType = request
        .csr_type
        .parse()
        .map_err(|e: opca_core::error::OpcaError| e.to_string())?;

    // Parse incoming CSR PEM
    let csr = X509Req::from_pem(request.csr_pem.as_bytes())
        .map_err(|e| format!("Failed to parse CSR PEM: {e}"))?;

    // Determine CN
    let cn = request
        .cn
        .or_else(|| csr_cn(&csr))
        .ok_or("CSR has no CN and no CN override was provided")?;

    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    // Sign CSR with CA
    let signed_cert = ca.sign_certificate(&csr, &cert_type).map_err(|e| {
        state.log_err("sign_csr", Some(e.to_string()));
        e.to_string()
    })?;

    let cert_pem_bytes = signed_cert
        .to_pem()
        .map_err(|e| format!("Failed to encode signed certificate: {e}"))?;
    let cert_pem = String::from_utf8_lossy(&cert_pem_bytes).to_string();

    // Build a CertificateBundle with cert + CSR (no private key — third-party CSR)
    let bundle = CertificateBundle::import(
        cert_type.clone(),
        &cn,
        &cert_pem_bytes,
        None, // no private key
        Some(request.csr_pem.as_bytes()),
        None, // no passphrase
        CertBundleConfig::default(),
    )
    .map_err(|e| {
        state.log_err("sign_csr", Some(e.to_string()));
        e.to_string()
    })?;

    // Store signed cert in 1Password + database
    ca.store_certbundle_for(&bundle, None, None, true)
        .map_err(|e| {
            state.log_err("sign_csr", Some(e.to_string()));
            e.to_string()
        })?;

    state.log_ok(
        "sign_csr",
        Some(format!("Signed {} CSR '{}'", cert_type, cn)),
    );

    let serial = bundle
        .get_certificate_attrib("serial")
        .ok()
        .flatten()
        .unwrap_or_default();

    Ok(SignCsrResult {
        cert: CertListItem {
            serial: Some(serial),
            cn: Some(cn),
            title: Some(bundle.title.clone()),
            status: Some("Valid".to_string()),
            cert_type: Some(cert_type.to_string()),
            expiry_date: bundle.get_certificate_attrib("not_after").ok().flatten(),
            key_type: bundle.get_certificate_attrib("key_type").ok().flatten(),
            key_size: bundle
                .get_certificate_attrib("key_size")
                .ok()
                .flatten()
                .and_then(|s| s.parse().ok()),
        },
        cert_pem,
    })
}

#[tauri::command]
pub async fn import_csr_cert(
    state: State<'_, AppState>,
    request: ImportCsrCertRequest,
) -> Result<CertListItem, String> {
    // Parse the imported certificate
    let cert = X509::from_pem(request.cert_pem.as_bytes())
        .map_err(|e| format!("Failed to parse certificate PEM: {e}"))?;

    // Determine CN
    let cn = request
        .cn
        .or_else(|| cert_cn(&cert))
        .ok_or("No CN found in certificate and no CN override provided")?;

    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    // Retrieve CSR item from 1Password
    let csr_title = format!("CSR_{cn}");
    let item_json = ca
        .op
        .get_item(&csr_title, "json")
        .map_err(|e| format!("No existing entry '{}' found: {}", csr_title, e))?;

    let obj: serde_json::Value = serde_json::from_str(&item_json)
        .map_err(|e| format!("Failed to parse 1Password item: {e}"))?;

    let fields = obj
        .get("fields")
        .and_then(|f| f.as_array())
        .ok_or("No fields in 1Password item")?;

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

    let key_pem = key_pem_str.ok_or("No private key found in CSR item")?;
    let csr_pem = csr_pem_str.unwrap_or_default();

    // Validate certificate public key matches private key
    let private_key = PKey::private_key_from_pem(key_pem.as_bytes())
        .map_err(|e| format!("Failed to parse private key: {e}"))?;

    let cert_pub_der = cert
        .public_key()
        .map_err(|e| format!("Failed to get certificate public key: {e}"))?
        .public_key_to_der()
        .map_err(|e| format!("Failed to encode certificate public key: {e}"))?;
    let key_pub_der = private_key
        .public_key_to_der()
        .map_err(|e| format!("Failed to encode private key public key: {e}"))?;

    if cert_pub_der != key_pub_der {
        return Err(
            "Certificate public key does not match the private key from the CSR".to_string(),
        );
    }

    // Delete the old CSR-only item
    ca.op.delete_item(&csr_title, true).map_err(|e| {
        state.log_err("import_csr_cert", Some(e.to_string()));
        e.to_string()
    })?;

    // Build certificate bundle with cert + key + CSR
    let bundle = CertificateBundle::import(
        CertType::External,
        &cn,
        request.cert_pem.as_bytes(),
        Some(key_pem.as_bytes()),
        Some(csr_pem.as_bytes()),
        None, // no passphrase
        CertBundleConfig::default(),
    )
    .map_err(|e| {
        state.log_err("import_csr_cert", Some(e.to_string()));
        e.to_string()
    })?;

    // Extract issuer info
    let issuer = cert_issuer_cn(&cert).unwrap_or_else(|| "Unknown".to_string());
    let issuer_subj = cert_issuer_subject(&cert);

    // Store as external certificate
    ca.store_certbundle_for(&bundle, Some(&issuer), Some(&issuer_subj), false)
        .map_err(|e| {
            state.log_err("import_csr_cert", Some(e.to_string()));
            e.to_string()
        })?;

    // Update CSR status
    let db = ca
        .ca_database
        .as_ref()
        .ok_or("Database not loaded")?;
    db.update_csr(&CsrRecord {
        cn: Some(cn.clone()),
        status: Some("Complete".to_string()),
        ..Default::default()
    })
    .map_err(|e| e.to_string())?;

    ca.store_ca_database().map_err(|e| {
        state.log_err("import_csr_cert", Some(e.to_string()));
        e.to_string()
    })?;

    state.log_ok(
        "import_csr_cert",
        Some(format!("Imported external certificate for '{}'", cn)),
    );

    let serial = bundle
        .get_certificate_attrib("serial")
        .ok()
        .flatten()
        .unwrap_or_default();

    Ok(CertListItem {
        serial: Some(serial),
        cn: Some(cn),
        title: Some(bundle.title.clone()),
        status: Some("Valid".to_string()),
        cert_type: Some(CertType::External.to_string()),
        expiry_date: bundle.get_certificate_attrib("not_after").ok().flatten(),
        key_type: bundle.get_certificate_attrib("key_type").ok().flatten(),
        key_size: bundle
            .get_certificate_attrib("key_size")
            .ok()
            .flatten()
            .and_then(|s| s.parse().ok()),
    })
}
