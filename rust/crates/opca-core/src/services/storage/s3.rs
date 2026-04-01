//! Amazon S3 storage backend.
//!
//! Uploads content to AWS S3 buckets using the native AWS SDK.  Credentials
//! are obtained from 1Password via the `op` CLI plugin (see
//! [`super::get_aws_credentials`]).
//!
//! URI format: `s3://bucket/key/prefix`

use log::{debug, error, info};

use crate::error::OpcaError;

use super::{AwsCredentials, StorageBackend};

/// S3-based storage backend.
pub struct StorageS3 {
    credentials: AwsCredentials,
}

impl StorageS3 {
    /// Create a new S3 backend with the given credentials.
    pub fn new(credentials: AwsCredentials) -> Self {
        Self { credentials }
    }

    /// Build an AWS SDK S3 client from the stored credentials.
    fn sdk_client(&self) -> aws_sdk_s3::Client {
        use aws_credential_types::Credentials;

        let region = self.credentials.region.as_deref().unwrap_or("ap-southeast-2");

        let creds = Credentials::new(
            &self.credentials.access_key_id,
            &self.credentials.secret_access_key,
            self.credentials.session_token.clone(),
            None, // expiry
            "opca-1password",
        );

        let config = aws_sdk_s3::config::Builder::new()
            .region(aws_sdk_s3::config::Region::new(region.to_string()))
            .credentials_provider(creds)
            .build();

        aws_sdk_s3::Client::from_conf(config)
    }
}

/// Run an async future on the current tokio runtime (if one exists) or
/// create a temporary one.  This avoids panicking when called from inside
/// a Tauri async command handler.
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        // We are already inside a tokio runtime (e.g. Tauri).
        // Use block_in_place so we don't block an async worker.
        tokio::task::block_in_place(|| handle.block_on(fut))
    } else {
        // No runtime — create a lightweight one.
        tokio::runtime::Runtime::new()
            .expect("failed to create tokio runtime")
            .block_on(fut)
    }
}

impl StorageBackend for StorageS3 {
    fn upload(&self, content: &[u8], uri: &str) -> Result<(), OpcaError> {
        info!("[s3] uploading {} bytes to {}", content.len(), uri);
        let (bucket_name, key) = parse_s3_uri(uri)?;
        let client = self.sdk_client();

        block_on(async {
            client
                .put_object()
                .bucket(&bucket_name)
                .key(&key)
                .body(content.to_vec().into())
                .send()
                .await
                .map_err(|e| {
                    error!("[s3] put_object failed for {uri}: {e}");
                    OpcaError::Storage(format!("S3 put_object failed: {e}"))
                })?;

            debug!("[s3] upload succeeded for {uri}");
            Ok(())
        })
    }

    fn test_connection(&self, uri: &str) -> Result<(), OpcaError> {
        info!("[s3] testing connection to {}", uri);
        let (bucket_name, _key) = parse_s3_uri(uri)?;
        let client = self.sdk_client();

        block_on(async {
            client
                .list_objects_v2()
                .bucket(&bucket_name)
                .delimiter("/")
                .max_keys(1)
                .send()
                .await
                .map_err(|e| {
                    error!("[s3] connection test failed for {uri}: {e}");
                    OpcaError::Storage(format!("S3 connection test failed: {e}"))
                })?;

            debug!("[s3] connection test passed for {uri}");
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// URI parsing
// ---------------------------------------------------------------------------

/// Parse an `s3://bucket/key` URI into (bucket, key).
fn parse_s3_uri(uri: &str) -> Result<(String, String), OpcaError> {
    let rest = uri
        .strip_prefix("s3://")
        .ok_or_else(|| OpcaError::Storage(format!("Invalid S3 URI: {uri}")))?;

    let (bucket, key) = rest
        .split_once('/')
        .ok_or_else(|| OpcaError::Storage(format!("S3 URI missing key path: {uri}")))?;

    if bucket.is_empty() {
        return Err(OpcaError::Storage("Empty S3 bucket name".into()));
    }

    Ok((bucket.to_string(), key.to_string()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_s3_uri() {
        let (bucket, key) = parse_s3_uri("s3://my-bucket/prefix/file.pem").unwrap();
        assert_eq!(bucket, "my-bucket");
        assert_eq!(key, "prefix/file.pem");
    }

    #[test]
    fn test_parse_s3_uri_root_key() {
        let (bucket, key) = parse_s3_uri("s3://my-bucket/file.pem").unwrap();
        assert_eq!(bucket, "my-bucket");
        assert_eq!(key, "file.pem");
    }

    #[test]
    fn test_parse_s3_uri_trailing_slash() {
        let (bucket, key) = parse_s3_uri("s3://my-bucket/prefix/").unwrap();
        assert_eq!(bucket, "my-bucket");
        assert_eq!(key, "prefix/");
    }

    #[test]
    fn test_parse_s3_uri_no_key() {
        let result = parse_s3_uri("s3://my-bucket");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_s3_uri_empty_bucket() {
        let result = parse_s3_uri("s3:///key");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_s3_uri_wrong_scheme() {
        let result = parse_s3_uri("rsync://host/path");
        assert!(result.is_err());
    }
}
