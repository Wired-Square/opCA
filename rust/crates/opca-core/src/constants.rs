/// 1Password field configuration.
///
/// These labels must match exactly what the Python version writes,
/// otherwise the Rust and Python implementations cannot share a vault.
pub struct OpConf {
    pub category: &'static str,
    pub ca_title: &'static str,
    pub ca_database_title: &'static str,
    pub ca_database_filename: &'static str,
    pub crl_title: &'static str,
    pub crl_filename: &'static str,
    pub openvpn_title: &'static str,
    pub cn_item: &'static str,
    pub subject_item: &'static str,
    pub key_item: &'static str,
    pub key_size_item: &'static str,
    pub cert_item: &'static str,
    pub cert_type_item: &'static str,
    pub ca_cert_item: &'static str,
    pub chain_item: &'static str,
    pub csr_item: &'static str,
    pub start_date_item: &'static str,
    pub expiry_date_item: &'static str,
    pub serial_item: &'static str,
    pub dh_item: &'static str,
    pub dh_key_size_item: &'static str,
    pub ta_item: &'static str,
    pub ta_key_size_item: &'static str,
    pub lock_title: &'static str,
}

pub const DEFAULT_OP_CONF: OpConf = OpConf {
    category: "Secure Note",
    ca_title: "CA",
    ca_database_title: "CA_Database",
    ca_database_filename: "ca-db-export.sql",
    crl_title: "CRL",
    crl_filename: "crl.pem",
    openvpn_title: "OpenVPN",
    cn_item: "cn[text]",
    subject_item: "subject[text]",
    key_item: "private_key",
    key_size_item: "key_size[text]",
    cert_item: "certificate",
    cert_type_item: "type[text]",
    ca_cert_item: "ca_certificate",
    chain_item: "certificate_chain",
    csr_item: "certificate_signing_request",
    start_date_item: "not_before[text]",
    expiry_date_item: "not_after[text]",
    serial_item: "serial[text]",
    dh_item: "diffie-hellman.dh_parameters",
    dh_key_size_item: "diffie-hellman.key_size[text]",
    ta_item: "tls_authentication.static_key",
    ta_key_size_item: "tls_authentication.key_size[text]",
    lock_title: "CA_Lock",
};

/// Default key sizes by certificate/key type.
pub struct KeySizeDefaults {
    pub ca: u32,
    pub dh: u32,
    pub dkim: u32,
    pub ta: u32,
    pub appledev: u32,
    pub device: u32,
    pub vpnclient: u32,
    pub vpnserver: u32,
    pub webserver: u32,
}

pub const DEFAULT_KEY_SIZE: KeySizeDefaults = KeySizeDefaults {
    ca: 4096,
    dh: 2048,
    dkim: 2048,
    ta: 2048,
    appledev: 2048,
    device: 2048,
    vpnclient: 2048,
    vpnserver: 2048,
    webserver: 2048,
};

/// Default filenames for published artefacts.
pub struct StorageConf {
    pub ca_cert_file: &'static str,
    pub crl_file: &'static str,
}

pub const DEFAULT_STORAGE_CONF: StorageConf = StorageConf {
    ca_cert_file: "ca.crt",
    crl_file: "crl.pem",
};

/// 1Password CLI binary name.
pub const OP_BIN: &str = "op";

/// Region used for S3 and Route53 when neither the CA config
/// (`ca_aws_region`) nor the credential item names one.
pub const DEFAULT_AWS_REGION: &str = "ap-southeast-2";

/// Process exit codes matching the Python conventions.
pub const EXIT_OK: i32 = 0;
pub const EXIT_VALIDATION_ERROR: i32 = 1;
pub const EXIT_FATAL: i32 = 2;
