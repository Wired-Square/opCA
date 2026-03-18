mod app;
mod commands;
mod output;

use clap::{Args, Parser, Subcommand};

use opca_core::constants::{EXIT_FATAL, EXIT_OK, EXIT_VALIDATION_ERROR};
use opca_core::error::OpcaError;

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "opca", about = "1Password Certificate Authority", version)]
pub struct Cli {
    /// 1Password Account (e.g. company.1password.com)
    #[arg(short = 'a', long, global = true)]
    pub account: Option<String>,

    /// CA Vault
    #[arg(short = 'v', long)]
    pub vault: String,

    /// Set logging verbosity
    #[arg(long, default_value = "info",
          value_parser = ["critical", "error", "warning", "info", "debug"])]
    pub log_level: String,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Certificate Authority operations
    Ca(CaArgs),
    /// Certificate operations
    Cert(CertArgs),
    /// Certificate Revocation List operations
    Crl(CrlArgs),
    /// Certificate Signing Request operations
    Csr(CsrArgs),
    /// Database operations
    Database(DatabaseArgs),
    /// DKIM key management
    Dkim(DkimArgs),
    /// OpenVPN artefact management
    Openvpn(OpenvpnArgs),
    /// Vault backup and restore
    Vault(VaultArgs),
}

// ---------------------------------------------------------------------------
// CA
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct CaArgs {
    #[command(subcommand)]
    pub action: CaAction,
}

#[derive(Subcommand)]
pub enum CaAction {
    /// Initialise a 1Password Certificate Authority
    Init {
        /// x509 Common Name attribute
        #[arg(short = 'n', long)]
        cn: String,

        /// Organisation name
        #[arg(short = 'o', long)]
        org: String,

        /// Number of days the CA certificate is valid for
        #[arg(long)]
        ca_days: i64,

        /// Number of days a CRL is valid for
        #[arg(long)]
        crl_days: i64,

        /// Number of days certificates signed by this CA are valid for
        #[arg(long)]
        days: i64,

        /// Email address for the certificate subject
        #[arg(short = 'e', long)]
        email: Option<String>,

        /// Organisational Unit
        #[arg(long)]
        ou: Option<String>,

        /// City
        #[arg(long)]
        city: Option<String>,

        /// State
        #[arg(long)]
        state: Option<String>,

        /// Country
        #[arg(long)]
        country: Option<String>,

        /// URL where the CA certificate can be found
        #[arg(long)]
        ca_url: Option<String>,

        /// URL where the CRL can be found
        #[arg(long)]
        crl_url: Option<String>,
    },

    /// Import a Certificate Authority from file
    Import {
        /// Certificate file
        #[arg(short = 'c', long)]
        cert_file: String,

        /// Private Key file
        #[arg(short = 'k', long)]
        key_file: String,

        /// Number of days certificates should be valid for
        #[arg(long)]
        days: i64,

        /// Number of days a CRL is valid for
        #[arg(long)]
        crl_days: i64,

        /// CA next serial number
        #[arg(long)]
        serial: Option<i64>,

        /// CA next CRL serial number
        #[arg(long)]
        crl_serial: Option<i64>,

        /// URL where the CA certificate can be found
        #[arg(long)]
        ca_url: Option<String>,

        /// URL where the CRL can be found
        #[arg(long)]
        crl_url: Option<String>,
    },

    /// Export the CA Certificate
    Export {
        /// Include the CA private key
        #[arg(long)]
        with_key: bool,

        /// Export certificate only (default)
        #[arg(long)]
        cert_only: bool,

        /// Write output to stdout
        #[arg(long)]
        to_stdout: bool,

        /// Write certificate PEM to this file
        #[arg(long)]
        cert_out: Option<String>,

        /// Write private key PEM to this file (requires --with-key)
        #[arg(long)]
        key_out: Option<String>,
    },

    /// List certificates signed by the CA
    List {
        /// List all certificates (default)
        #[arg(long, group = "list_mode")]
        all: bool,

        /// List expired certificates
        #[arg(short = 'e', long, group = "list_mode")]
        expired: bool,

        /// List revoked certificates
        #[arg(short = 'r', long, group = "list_mode")]
        revoked: bool,

        /// List certificates expiring soon
        #[arg(short = 'x', long, group = "list_mode")]
        expiring: bool,

        /// List valid certificates
        #[arg(long, group = "list_mode")]
        valid: bool,

        /// Filter by CN
        #[arg(short = 'n', long)]
        cn: Option<String>,

        /// Filter by serial number
        #[arg(short = 's', long)]
        serial: Option<String>,
    },

    /// Re-sign the CA certificate with the same key but new validity dates
    Resign {
        /// Number of days the new CA certificate is valid for
        #[arg(long)]
        ca_days: i64,
    },

    /// Upload the CA Certificate to the public store
    Upload {
        /// Store location (e.g. s3://bucket/key)
        #[arg(long)]
        store: Vec<String>,
    },
}

// ---------------------------------------------------------------------------
// Cert
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct CertArgs {
    #[command(subcommand)]
    pub action: CertAction,
}

#[derive(Subcommand)]
pub enum CertAction {
    /// Create a new x509 Certificate
    Create(CertCreateArgs),

    /// Export a x509 Certificate
    Export(CertExportArgs),

    /// Show certificate information
    Info(CertIdentifier),

    /// Import a x509 Certificate
    Import {
        /// Certificate file
        #[arg(short = 'c', long)]
        cert_file: String,

        /// Private Key file
        #[arg(short = 'k', long)]
        key_file: Option<String>,

        /// CN override
        #[arg(short = 'n', long)]
        cn: Option<String>,

        /// Import an external certificate (not signed by this CA)
        #[arg(long)]
        external: bool,
    },

    /// Rekey a x509 certificate (renew with a new private key)
    Rekey(CertIdentifier),

    /// Renew a x509 certificate
    Renew(CertIdentifier),

    /// Revoke a x509 certificate
    Revoke(CertRevokeArgs),
}

#[derive(Args)]
pub struct CertCreateArgs {
    /// CN attribute
    #[arg(short = 'n', long, group = "cert_source")]
    pub cn: Option<String>,

    /// Bulk host file
    #[arg(short = 'f', long, group = "cert_source")]
    pub file: Option<String>,

    /// Certificate type
    #[arg(short = 't', long, value_parser = ["device", "vpnserver", "vpnclient", "webserver"])]
    pub cert_type: String,

    /// Certificate serial number
    #[arg(short = 's', long)]
    pub serial: Option<i64>,

    /// Alternate CN
    #[arg(long = "alt")]
    pub alt: Vec<String>,
}

#[derive(Args)]
pub struct CertExportArgs {
    /// CN of the certificate
    #[arg(short = 'n', long, group = "cert_id")]
    pub cn: Option<String>,

    /// Serial number of the certificate
    #[arg(short = 's', long, group = "cert_id")]
    pub serial: Option<String>,

    /// Export format
    #[arg(short = 'f', long, default_value = "pem", value_parser = ["pem", "pkcs12"])]
    pub format: String,

    /// Include private key (PEM only)
    #[arg(long)]
    pub with_key: bool,

    /// Export certificate only (PEM only)
    #[arg(long)]
    pub cert_only: bool,

    /// Write to stdout
    #[arg(long)]
    pub to_stdout: bool,

    /// Write certificate PEM to this file
    #[arg(long)]
    pub cert_out: Option<String>,

    /// Write private key PEM to this file
    #[arg(long)]
    pub key_out: Option<String>,

    /// Output PKCS#12 file
    #[arg(short = 'o', long)]
    pub outfile: Option<String>,
}

#[derive(Args)]
pub struct CertIdentifier {
    /// CN of the certificate
    #[arg(short = 'n', long, group = "cert_id")]
    pub cn: Option<String>,

    /// Serial number of the certificate
    #[arg(short = 's', long, group = "cert_id")]
    pub serial: Option<String>,
}

#[derive(Args)]
pub struct CertRevokeArgs {
    /// Bulk host file
    #[arg(short = 'f', long, group = "revoke_source")]
    pub file: Option<String>,

    /// CN of the certificate
    #[arg(short = 'n', long, group = "revoke_source")]
    pub cn: Option<String>,

    /// Serial number of the certificate
    #[arg(short = 's', long, group = "revoke_source")]
    pub serial: Option<String>,
}

// ---------------------------------------------------------------------------
// CRL
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct CrlArgs {
    #[command(subcommand)]
    pub action: CrlAction,
}

#[derive(Subcommand)]
pub enum CrlAction {
    /// Generate a Certificate Revocation List
    Create,

    /// Export the Certificate Revocation List
    Export {
        /// Export format
        #[arg(short = 'f', long, default_value = "pem", value_parser = ["pem", "der"])]
        format: String,

        /// Write CRL to stdout
        #[arg(long, group = "crl_dest")]
        to_stdout: bool,

        /// Write CRL to this file
        #[arg(short = 'o', long, group = "crl_dest")]
        outfile: Option<String>,
    },

    /// Show CRL information
    Info,

    /// Upload the CRL to the public store
    Upload {
        /// Generate the CRL before uploading
        #[arg(long, visible_alias = "gen")]
        generate: bool,

        /// Store location (e.g. s3://bucket/key)
        #[arg(long)]
        store: Vec<String>,
    },
}

// ---------------------------------------------------------------------------
// CSR
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct CsrArgs {
    #[command(subcommand)]
    pub action: CsrAction,
}

#[derive(Subcommand)]
pub enum CsrAction {
    /// Generate a Certificate Signing Request
    Create {
        /// CSR type
        #[arg(short = 't', long, value_parser = ["appledev"])]
        csr_type: String,

        /// Common Name for the CSR subject
        #[arg(short = 'n', long)]
        cn: String,

        /// Email address for the CSR subject
        #[arg(long)]
        email: String,

        /// Country code (defaults to CA config if available)
        #[arg(long)]
        country: Option<String>,
    },

    /// Import a signed certificate into an existing CSR entry
    Import {
        /// CN override
        #[arg(short = 'n', long)]
        cn: Option<String>,

        /// Path to the signed certificate file
        #[arg(short = 'c', long)]
        cert_file: String,
    },

    /// Sign an external CSR with the local CA
    Sign {
        /// Path to CSR file (PEM or DER)
        #[arg(short = 'c', long)]
        csr_file: Option<String>,

        /// Inline CSR PEM string
        #[arg(long)]
        csr_pem: Option<String>,

        /// Certificate type
        #[arg(short = 't', long, default_value = "webserver",
              value_parser = ["appledev", "device", "vpnclient", "vpnserver", "webserver"])]
        csr_type: String,

        /// CN override
        #[arg(short = 'n', long)]
        cn: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct DatabaseArgs {
    #[command(subcommand)]
    pub action: DatabaseAction,
}

#[derive(Subcommand)]
pub enum DatabaseAction {
    /// Get the current CA Database configuration
    ConfigGet,

    /// Modify the CA Database configuration
    ConfigSet {
        /// Configuration attributes (e.g. --conf city=Canberra --conf days=30)
        #[arg(long, required = true)]
        conf: Vec<String>,
    },

    /// Export the entire CA SQLite database
    Export,

    /// Generate a Certificate Database for the CA
    Rebuild {
        /// Number of days certificates should be valid for
        #[arg(long)]
        days: i64,

        /// Number of days a CRL is valid for
        #[arg(long)]
        crl_days: i64,

        /// CA next serial number
        #[arg(long)]
        serial: Option<i64>,

        /// CA next CRL serial number
        #[arg(long)]
        crl_serial: Option<i64>,

        /// URL where the CA certificate can be found
        #[arg(long)]
        ca_url: Option<String>,

        /// URL where the CRL can be found
        #[arg(long)]
        crl_url: Option<String>,
    },

    /// Upload the CA Database to the private store
    Upload {
        /// Store location (e.g. s3://bucket/key)
        #[arg(long)]
        store: Vec<String>,
    },
}

// ---------------------------------------------------------------------------
// DKIM
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct DkimArgs {
    #[command(subcommand)]
    pub action: DkimAction,
}

#[derive(Subcommand)]
pub enum DkimAction {
    /// Generate a new DKIM key pair
    Create {
        /// Domain name
        #[arg(short = 'd', long)]
        domain: String,

        /// DKIM selector
        #[arg(short = 's', long)]
        selector: String,

        /// RSA key size in bits
        #[arg(short = 'k', long, default_value_t = 2048, value_parser = clap::value_parser!(u32).range(1024..=4096))]
        key_size: u32,

        /// Deploy the DKIM record to AWS Route53
        #[arg(long)]
        deploy_route53: bool,

        /// Route53 hosted zone ID
        #[arg(long)]
        zone_id: Option<String>,
    },

    /// Deploy DKIM key to Route53
    Deploy {
        /// Domain name
        #[arg(short = 'd', long)]
        domain: String,

        /// DKIM selector
        #[arg(short = 's', long)]
        selector: String,

        /// Route53 hosted zone ID
        #[arg(long)]
        zone_id: Option<String>,
    },

    /// Show DKIM key information
    Info {
        /// Domain name
        #[arg(short = 'd', long)]
        domain: String,

        /// DKIM selector
        #[arg(short = 's', long)]
        selector: String,
    },

    /// List all DKIM keys
    List {
        /// Filter by domain name
        #[arg(short = 'd', long)]
        domain: Option<String>,
    },

    /// Verify DKIM DNS record
    Verify {
        /// Domain name
        #[arg(short = 'd', long)]
        domain: String,

        /// DKIM selector
        #[arg(short = 's', long)]
        selector: String,
    },
}

// ---------------------------------------------------------------------------
// OpenVPN
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct OpenvpnArgs {
    #[command(subcommand)]
    pub action: OpenvpnAction,
}

#[derive(Subcommand)]
pub enum OpenvpnAction {
    /// Generate OpenVPN artefacts
    Generate {
        /// Generate Diffie-Hellman parameters
        #[arg(long)]
        dh: bool,

        /// Generate TLS Authentication static key
        #[arg(long)]
        ta_key: bool,

        /// Generate VPN profiles
        #[arg(long)]
        profile: bool,

        /// Generate a sample OpenVPN server object
        #[arg(long)]
        server: bool,

        /// Smart setup: create OpenVPN item with template, DH, and TA key
        #[arg(long)]
        setup: bool,

        /// Destination vault for profiles
        #[arg(short = 'd', long)]
        dest: Option<String>,

        /// Certificate CN (profile generation)
        #[arg(short = 'n', long, group = "profile_source")]
        cn: Option<String>,

        /// Bulk certificate CN file (profile generation)
        #[arg(short = 'f', long, group = "profile_source")]
        file: Option<String>,

        /// OpenVPN template name
        #[arg(short = 't', long)]
        template: Option<String>,
    },

    /// Retrieve OpenVPN artefacts
    Get {
        /// Retrieve Diffie-Hellman parameters
        #[arg(long)]
        dh: bool,

        /// Retrieve TLS Authentication static key
        #[arg(long)]
        ta_key: bool,

        /// Retrieve an OpenVPN template by name
        #[arg(short = 't', long)]
        template: Option<String>,
    },

    /// Import OpenVPN artefacts from files
    Import {
        /// Import Diffie-Hellman parameters
        #[arg(long)]
        dh: bool,

        /// Import TLS Authentication static key
        #[arg(long)]
        ta_key: bool,

        /// Generic input file
        #[arg(short = 'f', long)]
        file: Option<String>,

        /// DH parameters file
        #[arg(long)]
        dh_file: Option<String>,

        /// TLS Auth static key file
        #[arg(long)]
        ta_key_file: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// Vault
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct VaultArgs {
    #[command(subcommand)]
    pub action: VaultAction,
}

#[derive(Subcommand)]
pub enum VaultAction {
    /// Create an encrypted vault backup
    Backup {
        /// Output file path
        #[arg(short = 'o', long)]
        output: Option<String>,

        /// Encryption password (prompted if omitted)
        #[arg(long)]
        password: Option<String>,
    },

    /// Restore a vault from an encrypted backup
    Restore {
        /// Backup file to restore from
        #[arg(short = 'i', long)]
        input: String,

        /// Decryption password (prompted if omitted)
        #[arg(long)]
        password: Option<String>,
    },

    /// Display metadata from a backup file
    Info {
        /// Backup file to inspect
        #[arg(short = 'i', long)]
        input: String,

        /// Decryption password (prompted if omitted)
        #[arg(long)]
        password: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn init_logging(level: &str) {
    let filter = match level {
        "critical" => "error",
        "debug" => "debug",
        "warning" => "warn",
        "error" => "error",
        _ => "info",
    };
    env_logger::Builder::new()
        .filter_level(filter.parse().unwrap_or(log::LevelFilter::Info))
        .init();
}

fn main() {
    let cli = Cli::parse();
    init_logging(&cli.log_level);

    output::title(&format!(
        "opCA - 1Password Certificate Authority v{}",
        env!("CARGO_PKG_VERSION"),
    ));

    let code = match commands::dispatch(cli) {
        Ok(()) => EXIT_OK,
        Err(e) => {
            output::error(&e.to_string());
            match e {
                OpcaError::CaAlreadyExists
                | OpcaError::CertificateNotFound(_)
                | OpcaError::DuplicateCertificate(_)
                | OpcaError::InvalidCertificate(_)
                | OpcaError::CertificateRevoked(_)
                | OpcaError::CertificateExpired(_)
                | OpcaError::CsrNotFound(_) => EXIT_VALIDATION_ERROR,
                _ => EXIT_FATAL,
            }
        }
    };

    std::process::exit(code);
}
