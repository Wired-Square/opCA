use chrono::Utc;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

use opca_core::constants::DEFAULT_OP_CONF;
use opca_core::error::OpcaError;
use opca_core::op::{self, Error, Item, ItemRef, Runner, ShellRunner};
use opca_core::services::route53::{check_dkim_record, DkimDnsCheck, Route53Client};
use opca_core::services::storage::AwsCredentials;

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

/// The DKIM item, or `ItemNotFound` naming its title.
fn dkim_item<R: Runner>(app: &AppContext<R>, item_title: &str) -> Result<Item, OpcaError> {
    match app.vault()?.item(&ItemRef::title(item_title)) {
        Err(Error::ItemNotFound(_)) => Err(OpcaError::ItemNotFound(item_title.to_string())),
        found => Ok(found?),
    }
}

/// The AWS credentials for this CA, with its configured region applied.
fn aws_credentials<R: Runner>(app: &AppContext<R>) -> Result<AwsCredentials, OpcaError> {
    app.ca.as_ref().ok_or(OpcaError::CaNotFound)?.aws_credentials()
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

fn handle_create<R: Runner>(
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

    if app.vault()?.item_exists(&ItemRef::title(&item_title))? {
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

    let fields = [
        op::assign("domain[text]", &domain)?,
        op::assign("selector[text]", &selector)?,
        op::assign("key_size[text]", key_size)?,
        op::assign("private_key", &private_pem)?,
        op::assign("public_key[text]", &public_pem)?,
        op::assign("dns_record[text]", &dns_record)?,
        op::assign("dns_name[text]", &dns_name)?,
        op::assign("created_at[text]", &created_at)?,
    ];
    app.vault()?.create_item(&item_title, DEFAULT_OP_CONF.category, &fields)?;

    output::print_result(&format!("DKIM key '{item_title}' created"), true);

    // Deploy to Route53 if requested
    if deploy_route53 {
        let client = Route53Client::new(aws_credentials(app)?);
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| OpcaError::Other(format!("Failed to create runtime: {e}")))?;
        let result = rt.block_on(client.deploy_txt_record(&dns_name, &dns_record, DKIM_DNS_TTL))?;
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

fn handle_info<R: Runner>(
    app: &mut AppContext<R>,
    domain: String,
    selector: String,
) -> Result<(), OpcaError> {
    let item_title = make_dkim_title(&domain, &selector);
    let dns_name = make_dns_name(&domain, &selector);

    let item = dkim_item(app, &item_title)?;
    let read_field = |field: &str| op::field_text(&item, field).map(|s| s.trim().to_string());

    output::subtitle(&format!("DKIM Key: {domain} / {selector}"));
    output::info("Domain", &domain);
    output::info("Selector", &selector);
    output::info("Key Size", &read_field("key_size").unwrap_or_else(|| "N/A".to_string()));
    output::info("Created", &read_field("created_at").unwrap_or_else(|| "N/A".to_string()));
    output::info("DNS Name", &dns_name);
    output::info("DNS Record", &read_field("dns_record").unwrap_or_else(|| "N/A".to_string()));

    Ok(())
}

fn handle_deploy<R: Runner>(
    app: &mut AppContext<R>,
    domain: String,
    selector: String,
    _zone_id: Option<String>,
) -> Result<(), OpcaError> {
    output::title("Deploying DKIM Key to Route53");

    let item_title = make_dkim_title(&domain, &selector);
    let dns_name = make_dns_name(&domain, &selector);

    let item = dkim_item(app, &item_title)?;
    let dns_record = op::field_text(&item, "dns_record").unwrap_or_default().trim().to_string();

    let client = Route53Client::new(aws_credentials(app)?);
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| OpcaError::Other(format!("Failed to create runtime: {e}")))?;
    let result = rt.block_on(client.deploy_txt_record(&dns_name, &dns_record, DKIM_DNS_TTL))?;

    output::print_result(
        &format!("Deployed to zone {} (change: {})", result.zone_name, result.change_id),
        true,
    );
    output::warning("Run 'opca dkim verify' to confirm DNS propagation");

    Ok(())
}

fn handle_list<R: Runner>(
    app: &mut AppContext<R>,
    domain_filter: Option<String>,
) -> Result<(), OpcaError> {
    let items = app.vault()?.items(&[DEFAULT_OP_CONF.category])?;

    let mut dkim_items: Vec<(String, String, String)> = Vec::new();
    for item in &items {
        if let Some(rest) = item.title.strip_prefix(&format!("{DKIM_ITEM_PREFIX}_"))
            && let Some(pos) = rest.rfind('_') {
                let domain = &rest[..pos];
                let selector = &rest[pos + 1..];
                if !domain.is_empty() && !selector.is_empty() {
                    if let Some(ref filter) = domain_filter
                        && domain != filter.as_str() {
                            continue;
                        }
                    let created = item.created_at.get(..10).unwrap_or_default().to_string();
                    dkim_items.push((domain.to_string(), selector.to_string(), created));
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

fn handle_verify<R: Runner>(
    app: &mut AppContext<R>,
    domain: String,
    selector: String,
) -> Result<(), OpcaError> {
    output::title("Verifying DKIM DNS Record");

    let item_title = make_dkim_title(&domain, &selector);
    let dns_name = make_dns_name(&domain, &selector);

    let item = dkim_item(app, &item_title)?;
    let expected_record = op::field_text(&item, "dns_record").unwrap_or_default().trim().to_string();

    let check = tokio::runtime::Runtime::new()
        .map_err(|e| OpcaError::Other(format!("Failed to create runtime: {e}")))?
        .block_on(check_dkim_record(&dns_name, &expected_record))?;

    match check {
        DkimDnsCheck::Matches => output::print_result("DNS record verified — published and matching", true),
        DkimDnsCheck::NotPublished => {
            output::print_result("No TXT record found. DNS may not have propagated yet", false)
        }
        DkimDnsCheck::Mismatch { .. } => {
            output::print_result("TXT record found but does not match expected value", false)
        }
    }

    Ok(())
}
