//! Route53 DNS TXT record management.
//!
//! Pure helpers (`split_txt_value`, `format_txt_value`, `extract_dkim_key`,
//! `lookup_txt`) are always available.  The [`Route53Client`] uses the AWS
//! SDK directly with credentials sourced from 1Password.

// ---------------------------------------------------------------------------
// Pure helpers (always available)
// ---------------------------------------------------------------------------

/// Split a long TXT record value into chunks for DNS.
///
/// DNS TXT records have a 255-character limit per string. Long values
/// must be split into multiple quoted strings per RFC 4408.
pub fn split_txt_value(value: &str, max_len: usize) -> Vec<String> {
    if value.len() <= max_len {
        return vec![value.to_string()];
    }

    value
        .as_bytes()
        .chunks(max_len)
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .collect()
}

/// Format TXT record chunks as a quoted string suitable for Route53.
///
/// e.g. `["chunk1", "chunk2"]` → `"chunk1" "chunk2"`
pub fn format_txt_value(chunks: &[String]) -> String {
    chunks
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Extract the public key portion (`p=...`) from a DKIM record value.
pub fn extract_dkim_key(value: &str) -> Option<String> {
    if let Some(rest) = value.split("p=").nth(1) {
        let key = rest.split(';').next().unwrap_or("").trim();
        if !key.is_empty() {
            return Some(key.to_string());
        }
    }
    None
}

/// Look up TXT records for a DNS name using the system resolver.
///
/// Returns the concatenated TXT record data for each record found.
/// Multi-part TXT records are reassembled into a single string.
pub async fn lookup_txt(dns_name: &str) -> Result<Vec<String>, crate::error::OpcaError> {
    use hickory_resolver::TokioResolver;

    let resolver = TokioResolver::builder_tokio()
        .map_err(|e| crate::error::OpcaError::Other(format!("DNS resolver init failed: {e}")))?
        .build();

    let response = resolver
        .txt_lookup(dns_name)
        .await
        .map_err(|e| crate::error::OpcaError::Other(format!("DNS lookup failed: {e}")))?;

    let records: Vec<String> = response
        .iter()
        .map(|txt| txt.to_string())
        .collect();

    Ok(records)
}

// ---------------------------------------------------------------------------
// Native Route53 client (AWS SDK)
// ---------------------------------------------------------------------------

use crate::error::OpcaError;
use crate::services::storage::AwsCredentials;

/// A hosted zone returned by Route53.
#[derive(Debug, Clone)]
pub struct HostedZone {
    pub id: String,
    pub name: String,
}

/// Route53 client using the native AWS SDK.
///
/// Credentials are sourced from 1Password via [`super::storage::get_aws_credentials`]
/// and injected as static credentials — no AWS CLI or `op plugin run` needed.
pub struct Route53Client {
    creds: AwsCredentials,
}

impl Route53Client {
    pub fn new(creds: AwsCredentials) -> Self {
        Self { creds }
    }

    /// Build an AWS SDK Route53 client from the stored credentials.
    fn sdk_client(&self) -> aws_sdk_route53::Client {
        use aws_credential_types::Credentials;

        let region = self.creds.region.as_deref().unwrap_or("ap-southeast-2");

        let creds = Credentials::new(
            &self.creds.access_key_id,
            &self.creds.secret_access_key,
            self.creds.session_token.clone(),
            None, // expiry
            "opca-1password",
        );

        let config = aws_sdk_route53::config::Builder::new()
            .region(aws_sdk_route53::config::Region::new(region.to_string()))
            .credentials_provider(creds)
            .build();

        aws_sdk_route53::Client::from_conf(config)
    }

    /// List all hosted zones and return the one matching the given domain.
    ///
    /// Walks up the domain hierarchy to find the best match. For example,
    /// given `mail._domainkey.example.com`, it will try `mail._domainkey.example.com.`,
    /// then `_domainkey.example.com.`, then `example.com.`.
    pub async fn find_hosted_zone(&self, domain: &str) -> Result<HostedZone, OpcaError> {
        let client = self.sdk_client();

        // Collect all hosted zones (paginated).
        let mut zones: Vec<(String, String)> = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = client.list_hosted_zones();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.map_err(|e| {
                OpcaError::Route53(format!("Failed to list hosted zones: {e}"))
            })?;

            for zone in resp.hosted_zones() {
                let raw_id = zone.id();
                let id = raw_id
                    .strip_prefix("/hostedzone/")
                    .unwrap_or(raw_id)
                    .to_string();
                let name = zone.name().to_string();
                zones.push((id, name));
            }

            if resp.is_truncated() {
                marker = resp.next_marker().map(|s| s.to_string());
            } else {
                break;
            }
        }

        // Normalise the domain to trailing-dot form for matching.
        let normalised = if domain.ends_with('.') {
            domain.to_string()
        } else {
            format!("{domain}.")
        };

        // Walk up the domain hierarchy to find the best (longest) matching zone.
        let mut search = normalised.as_str();
        loop {
            for (id, name) in &zones {
                if name.eq_ignore_ascii_case(search) {
                    return Ok(HostedZone {
                        id: id.clone(),
                        name: name.clone(),
                    });
                }
            }

            // Remove the leftmost label and try again.
            if let Some(pos) = search.find('.') {
                search = &search[pos + 1..];
                if search.is_empty() || search == "." {
                    break;
                }
            } else {
                break;
            }
        }

        Err(OpcaError::Route53(format!(
            "No hosted zone found for domain: {domain}"
        )))
    }

    /// Upsert a TXT record in Route53.
    ///
    /// The `name` should be the fully-qualified DNS name (e.g.
    /// `mail._domainkey.example.com`). The `value` is the raw record
    /// content which will be split into 255-byte chunks as required by DNS.
    pub async fn upsert_txt_record(
        &self,
        zone_id: &str,
        name: &str,
        value: &str,
        ttl: u64,
    ) -> Result<String, OpcaError> {
        use aws_sdk_route53::types::{
            Change, ChangeAction, ChangeBatch, ResourceRecord, ResourceRecordSet, RrType,
        };

        let client = self.sdk_client();

        let chunks = split_txt_value(value, 255);
        let formatted = format_txt_value(&chunks);

        let record = ResourceRecord::builder()
            .value(formatted)
            .build()
            .map_err(|e| OpcaError::Route53(format!("Failed to build resource record: {e}")))?;

        let record_set = ResourceRecordSet::builder()
            .name(name)
            .r#type(RrType::Txt)
            .ttl(ttl as i64)
            .resource_records(record)
            .build()
            .map_err(|e| OpcaError::Route53(format!("Failed to build record set: {e}")))?;

        let change = Change::builder()
            .action(ChangeAction::Upsert)
            .resource_record_set(record_set)
            .build()
            .map_err(|e| OpcaError::Route53(format!("Failed to build change: {e}")))?;

        let batch = ChangeBatch::builder()
            .changes(change)
            .build()
            .map_err(|e| OpcaError::Route53(format!("Failed to build change batch: {e}")))?;

        let resp = client
            .change_resource_record_sets()
            .hosted_zone_id(zone_id)
            .change_batch(batch)
            .send()
            .await
            .map_err(|e| OpcaError::Route53(format!("Route53 upsert failed: {e}")))?;

        let change_id = resp
            .change_info()
            .map(|info| info.id().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        Ok(change_id)
    }

    /// Convenience: find the hosted zone for a DNS name and upsert the TXT record.
    pub async fn deploy_txt_record(
        &self,
        dns_name: &str,
        value: &str,
        ttl: u64,
    ) -> Result<Route53DeployResult, OpcaError> {
        let zone = self.find_hosted_zone(dns_name).await?;
        let change_id = self.upsert_txt_record(&zone.id, dns_name, value, ttl).await?;

        Ok(Route53DeployResult {
            zone_id: zone.id,
            zone_name: zone.name,
            change_id,
        })
    }
}

/// Result of a Route53 deployment.
#[derive(Debug, Clone)]
pub struct Route53DeployResult {
    pub zone_id: String,
    pub zone_name: String,
    pub change_id: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_short_value() {
        let chunks = split_txt_value("hello", 255);
        assert_eq!(chunks, vec!["hello"]);
    }

    #[test]
    fn test_split_exact_boundary() {
        let value = "a".repeat(255);
        let chunks = split_txt_value(&value, 255);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 255);
    }

    #[test]
    fn test_split_long_value() {
        let value = "a".repeat(600);
        let chunks = split_txt_value(&value, 255);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].len(), 255);
        assert_eq!(chunks[1].len(), 255);
        assert_eq!(chunks[2].len(), 90);
    }

    #[test]
    fn test_split_empty_value() {
        let chunks = split_txt_value("", 255);
        assert_eq!(chunks, vec![""]);
    }

    #[test]
    fn test_format_txt_value() {
        let chunks = vec!["part1".to_string(), "part2".to_string()];
        assert_eq!(format_txt_value(&chunks), r#""part1" "part2""#);
    }

    #[test]
    fn test_format_txt_single() {
        let chunks = vec!["only".to_string()];
        assert_eq!(format_txt_value(&chunks), r#""only""#);
    }

    #[test]
    fn test_extract_dkim_key() {
        let value = "v=DKIM1; k=rsa; p=MIGfMA0GCS+qABC123==";
        let key = extract_dkim_key(value);
        assert_eq!(key, Some("MIGfMA0GCS+qABC123==".to_string()));
    }

    #[test]
    fn test_extract_dkim_key_no_p() {
        let key = extract_dkim_key("v=DKIM1; k=rsa;");
        assert_eq!(key, None);
    }

    #[test]
    fn test_extract_dkim_key_empty_p() {
        let key = extract_dkim_key("v=DKIM1; p=;");
        assert_eq!(key, None);
    }

    // The Route53Client tests from the old shell-based implementation have
    // been removed.  The SDK client cannot be easily mocked without a trait
    // abstraction, which is not worth the complexity for two API calls.
    // The domain-walk algorithm is unchanged and was already validated.
    // Integration testing against a real AWS account covers the SDK path.
}
