use chrono::Utc;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use tauri::State;

use opca_core::constants::{DEFAULT_KEY_SIZE, DEFAULT_OP_CONF};
use opca_core::op::StoreAction;
use opca_core::services::route53::Route53Client;
use opca_core::services::storage::get_aws_credentials;

use crate::commands::dto::{
    CreateDkimRequest, CreateDkimResult, DkimKeyDetail, DkimKeyItem, DkimRoute53Result,
    DkimVerifyResult,
};
use crate::state::AppState;

/// 1Password item title prefix for DKIM keys.
const DKIM_ITEM_PREFIX: &str = "DKIM";

fn make_dkim_title(domain: &str, selector: &str) -> String {
    format!("{DKIM_ITEM_PREFIX}_{domain}_{selector}")
}

fn make_dns_name(domain: &str, selector: &str) -> String {
    format!("{selector}._domainkey.{domain}")
}

/// Format a PEM-encoded public key as a DKIM DNS TXT record value.
fn format_dkim_dns_record(public_key_pem: &str) -> String {
    let base64: String = public_key_pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    format!("v=DKIM1; k=rsa; p={base64}")
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn list_dkim_keys(state: State<'_, AppState>) -> Result<Vec<DkimKeyItem>, String> {
    state.with_op(|op| {
        let json_str = op
            .item_list(DEFAULT_OP_CONF.category, "json")
            .map_err(|e| e.to_string())?;

        let items: Vec<serde_json::Value> =
            serde_json::from_str(&json_str).map_err(|e| e.to_string())?;

        let mut dkim_items: Vec<DkimKeyItem> = Vec::new();
        for item in &items {
            let title = item["title"].as_str().unwrap_or_default();
            if let Some(rest) = title.strip_prefix(&format!("{DKIM_ITEM_PREFIX}_")) {
                // Title format: DKIM_domain_selector — split on last underscore
                if let Some(pos) = rest.rfind('_') {
                    let domain = &rest[..pos];
                    let selector = &rest[pos + 1..];
                    if !domain.is_empty() && !selector.is_empty() {
                        let created = item["created_at"]
                            .as_str()
                            .map(|s| s[..10].to_string());
                        dkim_items.push(DkimKeyItem {
                            domain: domain.to_string(),
                            selector: selector.to_string(),
                            created_at: created,
                        });
                    }
                }
            }
        }

        dkim_items.sort_by(|a, b| (&a.domain, &a.selector).cmp(&(&b.domain, &b.selector)));
        Ok(dkim_items)
    })
}

#[tauri::command]
pub async fn get_dkim_info(
    state: State<'_, AppState>,
    domain: String,
    selector: String,
) -> Result<DkimKeyDetail, String> {
    let item_title = make_dkim_title(&domain, &selector);
    let dns_name = make_dns_name(&domain, &selector);

    state.with_op(|op| {
        if !op.item_exists(&item_title) {
            return Err(format!("DKIM key '{}' not found.", item_title));
        }

        let read_field = |field: &str| -> Option<String> {
            let url = op.mk_url(&item_title, Some(field));
            op.read_item(&url).ok().map(|s| s.trim().to_string())
        };

        Ok(DkimKeyDetail {
            domain,
            selector,
            key_size: read_field("key_size"),
            dns_name,
            dns_record: read_field("dns_record"),
            created_at: read_field("created_at"),
            public_key: read_field("public_key"),
        })
    })
}

#[tauri::command]
pub async fn create_dkim_key(
    state: State<'_, AppState>,
    request: CreateDkimRequest,
) -> Result<CreateDkimResult, String> {
    let key_size = request.key_size.unwrap_or(DEFAULT_KEY_SIZE.dkim);
    let domain = request.domain;
    let selector = request.selector;
    let item_title = make_dkim_title(&domain, &selector);
    let dns_name = make_dns_name(&domain, &selector);

    let result = state.with_op(|op| {
        // Check for existing key
        if op.item_exists(&item_title) {
            return Err(format!(
                "DKIM key '{}' already exists. Delete it first or use a different selector.",
                item_title
            ));
        }

        // Generate RSA key pair
        let rsa = Rsa::generate(key_size)
            .map_err(|e| format!("Failed to generate RSA key: {e}"))?;
        let pkey = PKey::from_rsa(rsa)
            .map_err(|e| format!("Failed to wrap RSA key: {e}"))?;

        let private_pem = String::from_utf8(
            pkey.private_key_to_pem_pkcs8()
                .map_err(|e| format!("Failed to encode private key: {e}"))?,
        )
        .map_err(|e| e.to_string())?;

        let public_pem = String::from_utf8(
            pkey.public_key_to_pem()
                .map_err(|e| format!("Failed to encode public key: {e}"))?,
        )
        .map_err(|e| e.to_string())?;

        let dns_record = format_dkim_dns_record(&public_pem);
        let created_at = Utc::now().to_rfc3339();

        let attrs: Vec<String> = vec![
            format!("domain[text]={domain}"),
            format!("selector[text]={selector}"),
            format!("key_size[text]={key_size}"),
            format!("private_key={private_pem}"),
            format!("public_key[text]={public_pem}"),
            format!("dns_record[text]={dns_record}"),
            format!("dns_name[text]={dns_name}"),
            format!("created_at[text]={created_at}"),
        ];

        let attr_refs: Vec<&str> = attrs.iter().map(|s| s.as_str()).collect();

        op.store_item(
            &item_title,
            Some(&attr_refs),
            StoreAction::Create,
            DEFAULT_OP_CONF.category,
            None,
            None,
        )
        .map_err(|e| format!("Failed to store DKIM key in 1Password: {e}"))?;

        Ok((dns_name.clone(), dns_record, created_at))
    })?;

    let (dns_name_out, dns_record, created_at) = result;

    state.log_ok(
        "create_dkim",
        Some(format!("Created DKIM key for {selector}._domainkey.{domain}")),
    );

    Ok(CreateDkimResult {
        item: DkimKeyItem {
            domain,
            selector,
            created_at: Some(created_at[..10].to_string()),
        },
        dns_name: dns_name_out,
        dns_record,
    })
}

#[tauri::command]
pub async fn delete_dkim_key(
    state: State<'_, AppState>,
    domain: String,
    selector: String,
) -> Result<bool, String> {
    let item_title = make_dkim_title(&domain, &selector);

    state.with_op(|op| {
        if !op.item_exists(&item_title) {
            return Err(format!("DKIM key '{}' not found.", item_title));
        }

        op.delete_item(&item_title, true)
            .map_err(|e| format!("Failed to delete DKIM key: {e}"))?;

        Ok(true)
    })?;

    state.log_ok(
        "delete_dkim",
        Some(format!("Deleted DKIM key for {selector}._domainkey.{domain}")),
    );

    Ok(true)
}

#[tauri::command]
pub async fn verify_dkim_dns(
    state: State<'_, AppState>,
    domain: String,
    selector: String,
) -> Result<DkimVerifyResult, String> {
    let item_title = make_dkim_title(&domain, &selector);
    let dns_name = make_dns_name(&domain, &selector);

    // Read expected DNS record from 1Password
    let expected_record = state.with_op(|op| {
        if !op.item_exists(&item_title) {
            return Err(format!("DKIM key '{}' not found.", item_title));
        }

        let url = op.mk_url(&item_title, Some("dns_record"));
        let record = op.read_item(&url).map_err(|e| e.to_string())?;
        Ok(record.trim().to_string())
    })?;

    // Native DNS TXT lookup
    let found_records = opca_core::services::route53::lookup_txt(&dns_name)
        .await
        .map_err(|e| e.to_string())?;

    let expected_key = opca_core::services::route53::extract_dkim_key(&expected_record);

    let verified = found_records.iter().any(|rec| {
        match (&expected_key, opca_core::services::route53::extract_dkim_key(rec)) {
            (Some(ek), Some(fk)) => ek == &fk,
            _ => rec.contains(&expected_record),
        }
    });

    let found_txt = found_records.join("\n");
    let mismatch = !verified && !found_txt.is_empty();

    let message = if verified {
        "DNS record verified — published and matching.".to_string()
    } else if found_txt.is_empty() {
        "No TXT record found. DNS may not have propagated yet.".to_string()
    } else {
        "TXT record found but does not match the expected value.".to_string()
    };

    Ok(DkimVerifyResult {
        verified,
        dns_name,
        message,
        expected: if mismatch { Some(expected_record) } else { None },
        found: if mismatch { Some(found_txt) } else { None },
    })
}

/// Default TTL for DKIM TXT records (5 minutes).
const DKIM_DNS_TTL: u64 = 300;

#[tauri::command]
pub async fn deploy_dkim_route53(
    state: State<'_, AppState>,
    domain: String,
    selector: String,
) -> Result<DkimRoute53Result, String> {
    let item_title = make_dkim_title(&domain, &selector);
    let dns_name = make_dns_name(&domain, &selector);

    // Read the DNS record value from 1Password.
    let dns_record = state.with_op(|op| {
        if !op.item_exists(&item_title) {
            return Err(format!("DKIM key '{}' not found.", item_title));
        }

        let url = op.mk_url(&item_title, Some("dns_record"));
        let record = op.read_item(&url).map_err(|e| e.to_string())?;
        Ok(record.trim().to_string())
    })?;

    // Fetch AWS credentials from 1Password and deploy via native SDK.
    let creds = state.with_op(|op| {
        get_aws_credentials(op.runner(), op.account())
            .map_err(|e| e.to_string())
    })?;

    let client = Route53Client::new(creds);
    let result = client
        .deploy_txt_record(&dns_name, &dns_record, DKIM_DNS_TTL)
        .await
        .map_err(|e| e.to_string())?;

    let message = format!(
        "Deployed TXT record to zone {} (change: {})",
        result.zone_name, result.change_id
    );

    state.log_ok("deploy_dkim_route53", Some(message.clone()));

    Ok(DkimRoute53Result {
        dns_name,
        zone_name: result.zone_name,
        message,
    })
}
