//! Cryptographic utility functions — DH parameters, OpenVPN TA keys,
//! and X.509 certificate loading/inspection.

use openssl::dh::Dh;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::symm::Cipher;
use openssl::x509::X509;
use rand::RngCore;

use crate::error::OpcaError;

// ---------------------------------------------------------------------------
// DH parameters
// ---------------------------------------------------------------------------

/// Generate PEM-formatted Diffie–Hellman parameters (PKCS#3).
///
/// `key_size` is in bits (e.g. 2048). Returns a UTF-8 PEM string.
pub fn generate_dh_params(key_size: u32) -> Result<String, OpcaError> {
    let dh = Dh::generate_params(key_size, 2)
        .map_err(|e| OpcaError::Crypto(format!("DH parameter generation failed: {e}")))?;

    let pem = dh
        .params_to_pem()
        .map_err(|e| OpcaError::Crypto(format!("DH PEM encoding failed: {e}")))?;

    String::from_utf8(pem)
        .map_err(|e| OpcaError::Crypto(format!("DH PEM is not valid UTF-8: {e}")))
}

/// Verify PEM-formatted DH parameters and return the key size in bits.
pub fn verify_dh_params(pem: &[u8]) -> Result<u32, OpcaError> {
    let dh = Dh::params_from_pem(pem)
        .map_err(|e| OpcaError::Crypto(format!("Failed to parse DH parameters: {e}")))?;

    let bits = dh.prime_p().num_bits();
    Ok(bits as u32)
}

// ---------------------------------------------------------------------------
// OpenVPN TLS Authentication (TA) key
// ---------------------------------------------------------------------------

const TA_HEADER: &str = "-----BEGIN OpenVPN Static key V1-----";
const TA_FOOTER: &str = "-----END OpenVPN Static key V1-----";
const TA_LINE_LENGTH: usize = 32; // hex chars per line

/// Generate an OpenVPN static key (TA key) of the given bit size.
///
/// Returns a string in the standard OpenVPN static key format.
pub fn generate_ta_key(key_size: u32) -> Result<String, OpcaError> {
    let byte_count = (key_size / 8) as usize;
    let mut key_bytes = vec![0u8; byte_count];
    rand::rng().fill_bytes(&mut key_bytes);

    let hex_key: String = key_bytes.iter().map(|b| format!("{b:02x}")).collect();

    let mut lines = Vec::new();
    lines.push(TA_HEADER.to_string());
    for chunk in hex_key.as_bytes().chunks(TA_LINE_LENGTH) {
        lines.push(std::str::from_utf8(chunk).unwrap().to_string());
    }
    lines.push(TA_FOOTER.to_string());
    lines.push(String::new()); // trailing newline

    Ok(lines.join("\n"))
}

/// Verify an OpenVPN static key and return the key size in bits.
pub fn verify_ta_key(pem: &[u8]) -> Result<u32, OpcaError> {
    let text = std::str::from_utf8(pem)
        .map_err(|e| OpcaError::Crypto(format!("TA key is not valid UTF-8: {e}")))?;

    let content = text
        .split(TA_HEADER)
        .nth(1)
        .ok_or_else(|| OpcaError::Crypto("Missing OpenVPN Static key header".to_string()))?;

    let content = content
        .split(TA_FOOTER)
        .next()
        .ok_or_else(|| OpcaError::Crypto("Missing OpenVPN Static key footer".to_string()))?;

    let hex_string: String = content.chars().filter(|c| !c.is_whitespace()).collect();

    // Each hex char represents 4 bits
    Ok(hex_string.len() as u32 * 4)
}

// ---------------------------------------------------------------------------
// X.509 certificate helpers
// ---------------------------------------------------------------------------

/// Load a PEM-encoded X.509 certificate.
///
/// Returns an error if the data is missing PEM markers or cannot be parsed.
/// Re-encode a PEM private key as passphrase-encrypted PKCS#8 (AES-256-CBC).
pub fn encrypt_private_key_pem(pem: &str, passphrase: &str) -> Result<String, OpcaError> {
    let key = PKey::private_key_from_pem(pem.as_bytes())
        .map_err(|e| OpcaError::Crypto(format!("Failed to load private key: {e}")))?;
    let encrypted = key
        .private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), passphrase.as_bytes())
        .map_err(|e| OpcaError::Crypto(format!("Failed to encrypt private key: {e}")))?;
    String::from_utf8(encrypted).map_err(|e| OpcaError::Crypto(e.to_string()))
}

pub fn load_certificate_pem(pem: &[u8]) -> Result<X509, OpcaError> {
    let data = pem.to_vec();
    let trimmed = String::from_utf8_lossy(&data);
    let trimmed = trimmed.trim();

    if !trimmed.contains("-----BEGIN CERTIFICATE-----")
        || !trimmed.contains("-----END CERTIFICATE-----")
    {
        return Err(OpcaError::InvalidCertificate(
            "Certificate must be PEM with BEGIN/END CERTIFICATE markers.".to_string(),
        ));
    }

    X509::from_pem(pem)
        .map_err(|_| OpcaError::InvalidCertificate("Failed to parse PEM certificate.".to_string()))
}

/// Parse a PEM or DER certificate and return the Common Name, or `None`.
pub fn extract_certificate_cn(cert_bytes: &[u8]) -> Option<String> {
    let cert = X509::from_pem(cert_bytes)
        .or_else(|_| X509::from_der(cert_bytes))
        .ok()?;

    cert.subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|entry| entry.data().as_utf8().ok())
        .map(|s| s.to_string())
}

/// Generate a self-signed test certificate for unit tests.
#[cfg(test)]
fn generate_test_cert(cn: &str) -> Vec<u8> {
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509Builder, X509NameBuilder};

    let rsa = Rsa::generate(2048).unwrap();
    let key = PKey::from_rsa(rsa).unwrap();

    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder.append_entry_by_nid(Nid::COMMONNAME, cn).unwrap();
    let name = name_builder.build();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();

    let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
    builder.set_serial_number(&serial).unwrap();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();

    builder.sign(&key, MessageDigest::sha256()).unwrap();

    let cert = builder.build();
    cert.to_pem().unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_encrypted_key_opens_only_with_its_passphrase() {
        let key = crate::services::cert::CertificateBundle::generate_private_key(
            crate::services::cert::KeyAlgorithm::EcP256,
        )
        .unwrap();
        let plain = String::from_utf8(key.private_key_to_pem_pkcs8().unwrap()).unwrap();

        let encrypted = encrypt_private_key_pem(&plain, "correct horse").unwrap();

        assert!(encrypted.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
        let opened = PKey::private_key_from_pem_passphrase(encrypted.as_bytes(), b"correct horse").unwrap();
        assert!(opened.public_eq(&key));
        assert!(PKey::private_key_from_pem_passphrase(encrypted.as_bytes(), b"wrong").is_err());
    }

    #[test]
    fn test_generate_and_verify_ta_key_2048() {
        let ta = generate_ta_key(2048).unwrap();
        assert!(ta.contains(TA_HEADER));
        assert!(ta.contains(TA_FOOTER));

        let bits = verify_ta_key(ta.as_bytes()).unwrap();
        assert_eq!(bits, 2048);
    }

    #[test]
    fn test_generate_and_verify_ta_key_4096() {
        let ta = generate_ta_key(4096).unwrap();
        let bits = verify_ta_key(ta.as_bytes()).unwrap();
        assert_eq!(bits, 4096);
    }

    #[test]
    fn test_ta_key_format() {
        let ta = generate_ta_key(2048).unwrap();
        let lines: Vec<&str> = ta.lines().collect();

        assert_eq!(lines[0], TA_HEADER);
        assert_eq!(*lines.last().unwrap(), TA_FOOTER);

        // All content lines should be <= 32 hex chars
        for line in &lines[1..lines.len() - 1] {
            assert!(line.len() <= TA_LINE_LENGTH, "line too long: {line}");
            assert!(
                line.chars().all(|c| c.is_ascii_hexdigit()),
                "non-hex in line: {line}"
            );
        }
    }

    #[test]
    fn test_verify_ta_key_invalid() {
        let result = verify_ta_key(b"not a valid key");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_certificate_pem_valid() {
        let pem = generate_test_cert("Test CA");
        let cert = load_certificate_pem(&pem).unwrap();
        let cn = cert
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap()
            .data()
            .as_utf8()
            .unwrap();
        assert_eq!(cn.to_string(), "Test CA");
    }

    #[test]
    fn test_load_certificate_pem_missing_markers() {
        let result = load_certificate_pem(b"just some random data");
        assert!(result.is_err());
        match result.unwrap_err() {
            OpcaError::InvalidCertificate(msg) => assert!(msg.contains("markers")),
            other => panic!("Expected InvalidCertificate, got {other:?}"),
        }
    }

    #[test]
    fn test_extract_cn_from_pem() {
        let pem = generate_test_cert("My Common Name");
        let cn = extract_certificate_cn(&pem);
        assert_eq!(cn, Some("My Common Name".to_string()));
    }

    #[test]
    fn test_extract_cn_from_der() {
        let pem = generate_test_cert("DER Test");
        let cert = X509::from_pem(&pem).unwrap();
        let der = cert.to_der().unwrap();

        let cn = extract_certificate_cn(&der);
        assert_eq!(cn, Some("DER Test".to_string()));
    }

    #[test]
    fn test_extract_cn_invalid_data() {
        let cn = extract_certificate_cn(b"garbage");
        assert_eq!(cn, None);
    }

    // DH tests use small key sizes to keep them fast.
    // 512-bit is insecure but fine for testing parameter generation.

    #[test]
    fn test_generate_and_verify_dh_params() {
        let pem = generate_dh_params(512).unwrap();
        assert!(pem.contains("-----BEGIN DH PARAMETERS-----"));
        assert!(pem.contains("-----END DH PARAMETERS-----"));

        let bits = verify_dh_params(pem.as_bytes()).unwrap();
        assert_eq!(bits, 512);
    }

    #[test]
    fn test_verify_dh_params_invalid() {
        let result = verify_dh_params(b"not valid pem");
        assert!(result.is_err());
    }
}
