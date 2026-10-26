//! Route53 DNS TXT record management.
//!
//! The pure helper `extract_dkim_key` and the DKIM DNS check
//! (`check_dkim_record`) are always available.  The [`Route53Client`] uses
//! the AWS SDK directly with credentials sourced from 1Password.

// ---------------------------------------------------------------------------
// Pure helpers (always available)
// ---------------------------------------------------------------------------

/// The decoded public key (`p=`) of a DKIM record value; `None` when absent, revoked or unreadable.
pub fn extract_dkim_key(value: &str) -> Option<Vec<u8>> {
    wslib_dns_mail::dkim::parse(value)
        .record
        .public_key
        .filter(|key| !key.is_empty())
}

/// What DNS publishes at a DKIM name, against the record opCA holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkimDnsCheck {
    Matches,
    NotPublished,
    Mismatch { found: Vec<String> },
}

/// Compare the TXT records at `dns_name`, through the system resolver, with `expected`.
///
/// NXDOMAIN and NODATA are [`DkimDnsCheck::NotPublished`]; a lookup that could not
/// tell (SERVFAIL, REFUSED, timeout) is an [`OpcaError::Dns`].
pub async fn check_dkim_record(dns_name: &str, expected: &str) -> Result<DkimDnsCheck, OpcaError> {
    let resolver = HickoryResolver::from_system(HickoryOptions::default())
        .map_err(|e| OpcaError::Dns(format!("resolver init failed: {e}")))?;
    compare_dkim_record(&resolver, dns_name, expected).await
}

async fn compare_dkim_record(
    resolver: &impl Resolver,
    dns_name: &str,
    expected: &str,
) -> Result<DkimDnsCheck, OpcaError> {
    let found: Vec<String> = match resolver.txt(dns_name).await {
        Ok(answer) => answer.records.iter().map(Txt::joined).collect(),
        Err(e) if e.is_absent() => Vec::new(),
        Err(e) => return Err(OpcaError::Dns(format!("{dns_name}: {e}"))),
    };
    if found.is_empty() {
        return Ok(DkimDnsCheck::NotPublished);
    }
    let expected_key = extract_dkim_key(expected);
    let matches = found
        .iter()
        .any(|record| match (&expected_key, extract_dkim_key(record)) {
            (Some(expected_key), Some(found_key)) => *expected_key == found_key,
            _ => record.contains(expected),
        });
    Ok(if matches {
        DkimDnsCheck::Matches
    } else {
        DkimDnsCheck::Mismatch { found }
    })
}

// ---------------------------------------------------------------------------
// Native Route53 client (AWS SDK)
// ---------------------------------------------------------------------------

use log::{debug, error, info};
use wslib_dns::{HickoryOptions, HickoryResolver, Resolver, Txt, txt};

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
        let region = self.creds.region_or_default().to_string();

        let config = aws_sdk_route53::config::Builder::new()
            .behavior_version(aws_sdk_route53::config::BehaviorVersion::latest())
            .region(aws_sdk_route53::config::Region::new(region))
            .credentials_provider(self.creds.sdk_credentials())
            .build();

        aws_sdk_route53::Client::from_conf(config)
    }

    /// List all hosted zones and return the one matching the given domain.
    ///
    /// Walks up the domain hierarchy to find the best match. For example,
    /// given `mail._domainkey.example.com`, it will try `mail._domainkey.example.com.`,
    /// then `_domainkey.example.com.`, then `example.com.`.
    pub async fn find_hosted_zone(&self, domain: &str) -> Result<HostedZone, OpcaError> {
        info!("[route53] searching for hosted zone matching '{domain}'");
        let client = self.sdk_client();

        // Collect all hosted zones (paginated).
        let mut zones: Vec<(String, String)> = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = client.list_hosted_zones();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            debug!("[route53] listing hosted zones (marker: {marker:?})");
            let resp = req.send().await.map_err(|e| {
                error!("[route53] list_hosted_zones failed: {e}");
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

        debug!("[route53] found {} hosted zones", zones.len());

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
                    info!("[route53] matched zone '{name}' (id: {id}) for '{domain}'");
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

        info!("[route53] upserting TXT record for '{name}' in zone {zone_id} (TTL={ttl})");
        let client = self.sdk_client();

        let chunks = txt::split(value);
        let formatted = txt::quote(&chunks);
        debug!(
            "[route53] TXT value ({} chunks): {}",
            chunks.len(),
            &formatted[..formatted.len().min(120)]
        );

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
            .map_err(|e| {
                error!("[route53] upsert failed for '{name}': {e}");
                OpcaError::Route53(format!("Route53 upsert failed: {e}"))
            })?;

        let change_id = resp
            .change_info()
            .map(|info| info.id().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        info!("[route53] upsert succeeded for '{name}' (change: {change_id})");
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
        let change_id = self
            .upsert_txt_record(&zone.id, dns_name, value, ttl)
            .await?;

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
    use wslib_dns::{FakeResolver, LookupError};

    #[test]
    fn a_txt_value_quotes_as_one_string_up_to_255_octets() {
        assert_eq!(txt::quote(txt::split("hello")), r#""hello""#);
        let exact = "a".repeat(255);
        assert_eq!(txt::split(&exact), [exact.as_str()]);
    }

    #[test]
    fn a_long_txt_value_splits_into_255_octet_quoted_strings() {
        let value = "a".repeat(600);
        let chunks = txt::split(&value);
        assert_eq!(
            chunks.iter().map(|c| c.len()).collect::<Vec<_>>(),
            [255, 255, 90]
        );
        assert_eq!(
            txt::quote(&chunks),
            format!(
                r#""{}" "{}" "{}""#,
                "a".repeat(255),
                "a".repeat(255),
                "a".repeat(90)
            )
        );
    }

    #[test]
    fn an_empty_txt_value_quotes_as_one_empty_string() {
        assert_eq!(txt::quote(txt::split("")), r#""""#);
    }

    #[test]
    fn test_extract_dkim_key() {
        assert_eq!(
            extract_dkim_key("v=DKIM1; k=rsa; p=AQID"),
            Some(vec![1, 2, 3])
        );
    }

    #[test]
    fn a_dkim_key_split_by_whitespace_reads_as_one() {
        assert_eq!(
            extract_dkim_key("v=DKIM1; k=rsa; p=AQ ID"),
            extract_dkim_key("v=DKIM1; p=AQID")
        );
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

    const DKIM_NAME: &str = "mail._domainkey.example.com";
    const EXPECTED: &str = "v=DKIM1; k=rsa; p=AQID";

    fn check(resolver: FakeResolver) -> Result<DkimDnsCheck, OpcaError> {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(compare_dkim_record(&resolver, DKIM_NAME, EXPECTED))
    }

    #[test]
    fn a_published_key_split_across_strings_matches() {
        let resolver =
            FakeResolver::new().with_txt_strings(DKIM_NAME, ["v=DKIM1; k=rsa; ", "p=AQID"]);
        assert_eq!(check(resolver).unwrap(), DkimDnsCheck::Matches);
    }

    #[test]
    fn a_different_key_is_a_mismatch() {
        let resolver = FakeResolver::new().with_txt(DKIM_NAME, ["v=DKIM1; k=rsa; p=BAUG"]);
        let found = vec!["v=DKIM1; k=rsa; p=BAUG".to_string()];
        assert_eq!(check(resolver).unwrap(), DkimDnsCheck::Mismatch { found });
    }

    #[test]
    fn nxdomain_and_nodata_are_not_published() {
        assert_eq!(
            check(FakeResolver::new()).unwrap(),
            DkimDnsCheck::NotPublished
        );
        let nodata = FakeResolver::new().with_mx(DKIM_NAME, 10, "mx.example.com");
        assert_eq!(check(nodata).unwrap(), DkimDnsCheck::NotPublished);
    }

    #[test]
    fn a_lookup_that_cannot_tell_is_a_dns_error() {
        for error in [
            LookupError::ServFail,
            LookupError::Refused,
            LookupError::Timeout,
        ] {
            let resolver = FakeResolver::new().with_failure(DKIM_NAME, error);
            assert!(matches!(check(resolver), Err(OpcaError::Dns(_))));
        }
    }
}
