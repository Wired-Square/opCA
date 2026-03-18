use std::process::Command;

use chrono::Utc;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

use opca_core::constants::DEFAULT_OP_CONF;
use opca_core::error::OpcaError;
use opca_core::op::{CommandRunner, ShellRunner, StoreAction};
use opca_core::services::route53::{extract_dkim_key, Route53Client};

use crate::app::AppContext;
use crate::output;
use crate::{DkimAction, DkimArgs};

const DKIM_ITEM_PREFIX: &str = "DKIM";
const DKIM_DNS_TTL: u64 = 300;

fn make_dkim_title(domain: &str, selector: &str) -> String {
    format!("{DKIM_ITEM_PREFIX}_{domain}_{selector}")
}

fn make_dns_name(domain: &str, selector: &str) -> String {
    format!("{selector}._domainkey.{domain}")
}

fn format_dkim_dns_record(public_key_pem: &str) -> String {
    let base64: String = public_key_pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    format!("v=DKIM1; k=rsa; p={base64}")
}

pub fn dispatch(args: DkimArgs, app: &mut AppContext<ShellRunner>) -> Result<(), OpcaError> {
    match args.action {
        DkimAction::Create {
            domain,
            selector,
            key_size,
            deploy_route53,
            zone_id,
        } => handle_create(app, domain, selector, key_size, deploy_route53, zone_id),
        DkimAction::Deploy {
            domain,
            selector,
            zone_id,
        } => handle_deploy(app, domain, selector, zone_id),
        DkimAction::Info { domain, selector } => handle_info(app, domain, selector),
        DkimAction::List { domain } => handle_list(app, domain),
        DkimAction::Verify { domain, selector } => handle_verify(app, domain, selector),
    }
}

fn handle_create<R: CommandRunner>(
    app: &mut AppContext<R>,
    domain: String,
    selector: String,
    key_size: u32,
    deploy_route53: bool,
    _zone_id: Option<String>,
) -> Result<(), OpcaError> {
    output::title("Creating DKIM Key");

    let item_title = make_dkim_title(&domain, &selector);
    let dns_name = make_dns_name(&domain, &selector);

    let op = app.op()?;
    if op.item_exists(&item_title) {
        return Err(OpcaError::Other(format!(
            "DKIM key '{item_title}' already exists. Delete it first or use a different selector."
        )));
    }

    // Generate RSA key pair
    let rsa = Rsa::generate(key_size)
        .map_err(|e| OpcaError::Crypto(format!("Failed to generate RSA key: {e}")))?;
    let pkey = PKey::from_rsa(rsa)
        .map_err(|e| OpcaError::Crypto(format!("Failed to wrap RSA key: {e}")))?;

    let private_pem = String::from_utf8(
        pkey.private_key_to_pem_pkcs8()
            .map_err(|e| OpcaError::Crypto(format!("Failed to encode private key: {e}")))?,
    )
    .map_err(|e| OpcaError::Other(e.to_string()))?;

    let public_pem = String::from_utf8(
        pkey.public_key_to_pem()
            .map_err(|e| OpcaError::Crypto(format!("Failed to encode public key: {e}")))?,
    )
    .map_err(|e| OpcaError::Other(e.to_string()))?;

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

    let op = app.op()?;
    op.store_item(
        &item_title,
        Some(&attr_refs),
        StoreAction::Create,
        DEFAULT_OP_CONF.category,
        None,
        None,
    )?;

    output::print_result(&format!("DKIM key '{item_title}' created"), true);

    // Deploy to Route53 if requested
    if deploy_route53 {
        let op = app.op()?;
        let client = Route53Client::new(op.runner());
        let result = client.deploy_txt_record(&dns_name, &dns_record, DKIM_DNS_TTL)?;
        output::print_result(
            &format!("Deployed to Route53 zone {} (change: {})", result.zone_name, result.change_id),
            true,
        );
    }

    // Print summary
    println!();
    output::info("Domain", &domain);
    output::info("Selector", &selector);
    output::info("Key Size", &key_size.to_string());
    output::info("DNS Name", &dns_name);
    output::info("DNS Record", &dns_record);

    Ok(())
}

fn handle_info<R: CommandRunner>(
    app: &mut AppContext<R>,
    domain: String,
    selector: String,
) -> Result<(), OpcaError> {
    let item_title = make_dkim_title(&domain, &selector);
    let dns_name = make_dns_name(&domain, &selector);

    let op = app.op()?;
    if !op.item_exists(&item_title) {
        return Err(OpcaError::ItemNotFound(item_title));
    }

    let read_field = |field: &str| -> Option<String> {
        let url = op.mk_url(&item_title, Some(field));
        op.read_item(&url).ok().map(|s| s.trim().to_string())
    };

    output::subtitle(&format!("DKIM Key: {domain} / {selector}"));
    output::info("Domain", &domain);
    output::info("Selector", &selector);
    output::info("Key Size", &read_field("key_size").unwrap_or_else(|| "N/A".to_string()));
    output::info("Created", &read_field("created_at").unwrap_or_else(|| "N/A".to_string()));
    output::info("DNS Name", &dns_name);
    output::info("DNS Record", &read_field("dns_record").unwrap_or_else(|| "N/A".to_string()));

    Ok(())
}

fn handle_deploy<R: CommandRunner>(
    app: &mut AppContext<R>,
    domain: String,
    selector: String,
    _zone_id: Option<String>,
) -> Result<(), OpcaError> {
    output::title("Deploying DKIM Key to Route53");

    let item_title = make_dkim_title(&domain, &selector);
    let dns_name = make_dns_name(&domain, &selector);

    let op = app.op()?;
    if !op.item_exists(&item_title) {
        return Err(OpcaError::ItemNotFound(item_title));
    }

    let url = op.mk_url(&item_title, Some("dns_record"));
    let dns_record = op.read_item(&url)?.trim().to_string();

    let client = Route53Client::new(op.runner());
    let result = client.deploy_txt_record(&dns_name, &dns_record, DKIM_DNS_TTL)?;

    output::print_result(
        &format!("Deployed to zone {} (change: {})", result.zone_name, result.change_id),
        true,
    );
    output::warning("Run 'opca dkim verify' to confirm DNS propagation");

    Ok(())
}

fn handle_list<R: CommandRunner>(
    app: &mut AppContext<R>,
    domain_filter: Option<String>,
) -> Result<(), OpcaError> {
    let op = app.op()?;
    let json_str = op.item_list(DEFAULT_OP_CONF.category, "json")?;
    let items: Vec<serde_json::Value> =
        serde_json::from_str(&json_str).map_err(|e| OpcaError::Other(e.to_string()))?;

    let mut dkim_items: Vec<(String, String, String)> = Vec::new();
    for item in &items {
        let title = item["title"].as_str().unwrap_or_default();
        if let Some(rest) = title.strip_prefix(&format!("{DKIM_ITEM_PREFIX}_")) {
            if let Some(pos) = rest.rfind('_') {
                let domain = &rest[..pos];
                let selector = &rest[pos + 1..];
                if !domain.is_empty() && !selector.is_empty() {
                    if let Some(ref filter) = domain_filter {
                        if domain != filter.as_str() {
                            continue;
                        }
                    }
                    let created = item["created_at"]
                        .as_str()
                        .map(|s| s[..10].to_string())
                        .unwrap_or_default();
                    dkim_items.push((domain.to_string(), selector.to_string(), created));
                }
            }
        }
    }

    dkim_items.sort();

    output::subtitle("DKIM Keys");
    let headers = &["Domain", "Selector", "Created"];
    let rows: Vec<Vec<String>> = dkim_items
        .iter()
        .map(|(d, s, c)| vec![d.clone(), s.clone(), c.clone()])
        .collect();
    output::print_table(headers, &rows);
    println!();
    println!("  Total: {} key(s)", rows.len());

    Ok(())
}

fn handle_verify<R: CommandRunner>(
    app: &mut AppContext<R>,
    domain: String,
    selector: String,
) -> Result<(), OpcaError> {
    output::title("Verifying DKIM DNS Record");

    let item_title = make_dkim_title(&domain, &selector);
    let dns_name = make_dns_name(&domain, &selector);

    let op = app.op()?;
    if !op.item_exists(&item_title) {
        return Err(OpcaError::ItemNotFound(item_title));
    }

    let url = op.mk_url(&item_title, Some("dns_record"));
    let expected_record = op.read_item(&url)?.trim().to_string();

    // DNS lookup using dig
    let dig_output = Command::new("dig")
        .args(["+short", "TXT", &dns_name])
        .output()
        .map_err(|e| OpcaError::Other(format!("Failed to run dig: {e}")))?;

    let stdout = String::from_utf8_lossy(&dig_output.stdout);

    let expected_key = extract_dkim_key(&expected_record);
    let verified = if let Some(ref ek) = expected_key {
        stdout.contains(ek)
    } else {
        stdout.contains(&expected_record)
    };

    if verified {
        output::print_result("DNS record verified — published and matching", true);
    } else if stdout.trim().is_empty() {
        output::print_result("No TXT record found. DNS may not have propagated yet", false);
    } else {
        output::print_result("TXT record found but does not match expected value", false);
    }

    Ok(())
}
