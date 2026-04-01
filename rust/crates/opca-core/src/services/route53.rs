//! Route53 DNS TXT record management helpers.
//!
//! The `split_txt_value` function is always available. The `Route53` client
//! requires the `aws` feature and uses 1Password for AWS credentials.

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
// Route53 client (shells out to `aws` via `op plugin run`)
// ---------------------------------------------------------------------------

use crate::error::OpcaError;
use crate::op::CommandRunner;

/// A hosted zone returned by `aws route53 list-hosted-zones`.
#[derive(Debug, Clone)]
pub struct HostedZone {
    pub id: String,
    pub name: String,
}

/// Route53 client that uses the AWS CLI through the 1Password plugin.
///
/// All commands are executed via `op plugin run -- aws route53 ...` so
/// credentials are sourced from 1Password automatically.
pub struct Route53Client<'a, R: CommandRunner> {
    runner: &'a R,
}

impl<'a, R: CommandRunner> Route53Client<'a, R> {
    pub fn new(runner: &'a R) -> Self {
        Self { runner }
    }

    /// Run an AWS CLI command via the 1Password plugin and return stdout.
    fn aws_route53(&self, args: &[&str]) -> Result<String, OpcaError> {
        let mut full_args = vec!["plugin", "run", "--", "aws", "route53"];
        full_args.extend_from_slice(args);
        full_args.extend_from_slice(&["--output", "json"]);

        let output = self.runner.run("op", &full_args, None, None)?;

        if !output.success {
            let msg = if output.stderr.is_empty() {
                output.stdout.clone()
            } else {
                output.stderr.clone()
            };
            return Err(OpcaError::Route53(format!(
                "AWS Route53 command failed: {msg}"
            )));
        }

        Ok(output.stdout)
    }

    /// List all hosted zones and return those matching the given domain.
    ///
    /// Walks up the domain hierarchy to find the best match. For example,
    /// given `mail._domainkey.example.com`, it will try `mail._domainkey.example.com.`,
    /// then `_domainkey.example.com.`, then `example.com.`.
    pub fn find_hosted_zone(&self, domain: &str) -> Result<HostedZone, OpcaError> {
        let stdout = self.aws_route53(&["list-hosted-zones"])?;

        let parsed: serde_json::Value =
            serde_json::from_str(&stdout).map_err(|e| {
                OpcaError::Route53(format!("Failed to parse hosted zones response: {e}"))
            })?;

        let zones = parsed["HostedZones"]
            .as_array()
            .ok_or_else(|| OpcaError::Route53("No HostedZones array in response".into()))?;

        // Normalise the domain to a trailing-dot form for matching.
        let normalised = if domain.ends_with('.') {
            domain.to_string()
        } else {
            format!("{domain}.")
        };

        // Walk up the domain hierarchy to find the best (longest) matching zone.
        let mut search = normalised.as_str();
        loop {
            for zone in zones {
                let zone_name = zone["Name"].as_str().unwrap_or_default();
                if zone_name.eq_ignore_ascii_case(search) {
                    let raw_id = zone["Id"].as_str().unwrap_or_default();
                    // The Id field is "/hostedzone/Z12345" — strip the prefix.
                    let id = raw_id
                        .strip_prefix("/hostedzone/")
                        .unwrap_or(raw_id)
                        .to_string();
                    return Ok(HostedZone {
                        id,
                        name: zone_name.to_string(),
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
    pub fn upsert_txt_record(
        &self,
        zone_id: &str,
        name: &str,
        value: &str,
        ttl: u64,
    ) -> Result<String, OpcaError> {
        let chunks = split_txt_value(value, 255);
        let formatted = format_txt_value(&chunks);

        // Build the change-batch JSON.
        let change_batch = serde_json::json!({
            "Changes": [{
                "Action": "UPSERT",
                "ResourceRecordSet": {
                    "Name": name,
                    "Type": "TXT",
                    "TTL": ttl,
                    "ResourceRecords": [{
                        "Value": formatted
                    }]
                }
            }]
        });

        let batch_str = serde_json::to_string(&change_batch).map_err(|e| {
            OpcaError::Route53(format!("Failed to serialise change batch: {e}"))
        })?;

        let stdout = self.aws_route53(&[
            "change-resource-record-sets",
            "--hosted-zone-id",
            zone_id,
            "--change-batch",
            &batch_str,
        ])?;

        // Extract the change ID from the response for status tracking.
        let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_default();
        let change_id = parsed["ChangeInfo"]["Id"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();

        Ok(change_id)
    }

    /// Convenience: find the hosted zone for a DNS name and upsert the TXT record.
    pub fn deploy_txt_record(
        &self,
        dns_name: &str,
        value: &str,
        ttl: u64,
    ) -> Result<Route53DeployResult, OpcaError> {
        let zone = self.find_hosted_zone(dns_name)?;
        let change_id = self.upsert_txt_record(&zone.id, dns_name, value, ttl)?;

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

    // -----------------------------------------------------------------------
    // Route53Client tests
    // -----------------------------------------------------------------------

    use crate::op::{CommandOutput, CommandRunner};
    use std::cell::RefCell;
    use std::collections::HashMap;

    struct MockRunner {
        responses: RefCell<Vec<CommandOutput>>,
    }

    impl MockRunner {
        fn new(responses: Vec<CommandOutput>) -> Self {
            Self {
                responses: RefCell::new(responses),
            }
        }
    }

    impl CommandRunner for MockRunner {
        fn run(
            &self,
            _bin: &str,
            _args: &[&str],
            _input: Option<&str>,
            _env_vars: Option<&HashMap<String, String>>,
        ) -> Result<CommandOutput, crate::error::OpcaError> {
            let mut responses = self.responses.borrow_mut();
            if responses.is_empty() {
                Ok(CommandOutput {
                    stdout: String::new(),
                    stderr: String::new(),
                    success: true,
                })
            } else {
                Ok(responses.remove(0))
            }
        }
    }

    #[test]
    fn test_find_hosted_zone_exact_match() {
        let zones_json = r#"{
            "HostedZones": [
                { "Id": "/hostedzone/Z111", "Name": "other.com." },
                { "Id": "/hostedzone/Z222", "Name": "example.com." }
            ]
        }"#;
        let runner = MockRunner::new(vec![CommandOutput {
            stdout: zones_json.to_string(),
            stderr: String::new(),
            success: true,
        }]);
        let client = Route53Client::new(&runner);
        let zone = client.find_hosted_zone("example.com").unwrap();
        assert_eq!(zone.id, "Z222");
        assert_eq!(zone.name, "example.com.");
    }

    #[test]
    fn test_find_hosted_zone_subdomain_walk() {
        let zones_json = r#"{
            "HostedZones": [
                { "Id": "/hostedzone/Z333", "Name": "example.com." }
            ]
        }"#;
        let runner = MockRunner::new(vec![CommandOutput {
            stdout: zones_json.to_string(),
            stderr: String::new(),
            success: true,
        }]);
        let client = Route53Client::new(&runner);
        let zone = client
            .find_hosted_zone("mail._domainkey.example.com")
            .unwrap();
        assert_eq!(zone.id, "Z333");
    }

    #[test]
    fn test_find_hosted_zone_not_found() {
        let zones_json = r#"{ "HostedZones": [] }"#;
        let runner = MockRunner::new(vec![CommandOutput {
            stdout: zones_json.to_string(),
            stderr: String::new(),
            success: true,
        }]);
        let client = Route53Client::new(&runner);
        let result = client.find_hosted_zone("missing.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_upsert_txt_record() {
        let response_json = r#"{
            "ChangeInfo": {
                "Id": "/change/C12345",
                "Status": "PENDING"
            }
        }"#;
        let runner = MockRunner::new(vec![CommandOutput {
            stdout: response_json.to_string(),
            stderr: String::new(),
            success: true,
        }]);
        let client = Route53Client::new(&runner);
        let change_id = client
            .upsert_txt_record("Z222", "mail._domainkey.example.com", "v=DKIM1; k=rsa; p=ABC123", 300)
            .unwrap();
        assert_eq!(change_id, "/change/C12345");
    }

    #[test]
    fn test_aws_route53_failure() {
        let runner = MockRunner::new(vec![CommandOutput {
            stdout: String::new(),
            stderr: "access denied".to_string(),
            success: false,
        }]);
        let client = Route53Client::new(&runner);
        let result = client.find_hosted_zone("example.com");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("access denied"));
    }
}
