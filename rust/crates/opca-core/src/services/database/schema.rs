use rusqlite::Connection;

use crate::error::OpcaError;
use crate::utils::datetime::{self, DateTimeFormat};

use super::models::{MigrationInfo, MigrationStep};

pub const DEFAULT_SCHEMA_VERSION: i64 = 8;

// ---------------------------------------------------------------------------
// Table DDL (v8 — current)
// ---------------------------------------------------------------------------

pub const CREATE_CONFIG_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS config (
        id INTEGER PRIMARY KEY,
        next_serial TEXT,
        next_crl_serial TEXT,
        org TEXT,
        ou TEXT,
        email TEXT,
        city TEXT,
        state TEXT,
        country TEXT,
        ca_url TEXT,
        crl_url TEXT,
        days INTEGER,
        crl_days INTEGER,
        schema_version INTEGER,
        ca_public_store TEXT,
        ca_private_store TEXT,
        ca_backup_store TEXT
    )
";

pub const CREATE_CA_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS certificate_authority (
        serial TEXT PRIMARY KEY,
        cn TEXT,
        title TEXT,
        status TEXT,
        expiry_date TEXT,
        revocation_date TEXT,
        subject TEXT,
        cert_type TEXT,
        not_before TEXT,
        key_type TEXT,
        key_size INTEGER,
        issuer TEXT,
        san TEXT,
        ignored_at TEXT,
        ignored_by TEXT,
        ignored_reason TEXT,
        ignored_note TEXT
    )
";

pub const CREATE_CSR_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS csr (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cn TEXT,
        title TEXT,
        csr_type TEXT,
        email TEXT,
        subject TEXT,
        status TEXT,
        created_date TEXT,
        csr_pem TEXT
    )
";

pub const CREATE_EXTERNAL_CERT_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS external_certificate (
        serial TEXT PRIMARY KEY,
        cn TEXT,
        title TEXT,
        status TEXT,
        expiry_date TEXT,
        subject TEXT,
        issuer TEXT,
        issuer_subject TEXT,
        import_date TEXT,
        cert_type TEXT,
        not_before TEXT,
        key_type TEXT,
        key_size INTEGER,
        san TEXT
    )
";

pub const CREATE_CRL_METADATA_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS crl_metadata (
        id INTEGER PRIMARY KEY DEFAULT 1,
        issuer TEXT,
        last_update TEXT,
        next_update TEXT,
        crl_number INTEGER,
        revoked_count INTEGER DEFAULT 0,
        revoked_json TEXT
    )
";

pub const CREATE_OPENVPN_TEMPLATE_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS openvpn_template (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        content TEXT NOT NULL,
        updated_date TEXT
    )
";

pub const CREATE_OPENVPN_PROFILE_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS openvpn_profile (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cn TEXT NOT NULL,
        title TEXT NOT NULL,
        created_date TEXT,
        template TEXT
    )
";

// ---------------------------------------------------------------------------
// Indexes
// ---------------------------------------------------------------------------

pub const CREATE_INDEXES: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS idx_ca_cn ON certificate_authority (cn)",
    "CREATE INDEX IF NOT EXISTS idx_ca_title ON certificate_authority (title)",
    "CREATE INDEX IF NOT EXISTS idx_ca_status ON certificate_authority (status)",
    "CREATE INDEX IF NOT EXISTS idx_csr_cn ON csr (cn)",
    "CREATE INDEX IF NOT EXISTS idx_csr_status ON csr (status)",
    "CREATE INDEX IF NOT EXISTS idx_ext_cn ON external_certificate (cn)",
    "CREATE INDEX IF NOT EXISTS idx_ext_status ON external_certificate (status)",
];

// ---------------------------------------------------------------------------
// Schema migration
// ---------------------------------------------------------------------------

/// Run schema migrations from `current_version` up to [`DEFAULT_SCHEMA_VERSION`].
///
/// Each step is applied sequentially using `if` (not `else if`) so that a v1
/// database walks through every intermediate version, matching the Python
/// `import_database()` migration logic.
pub fn migrate(conn: &Connection, current_version: i64) -> Result<MigrationInfo, OpcaError> {
    let mut info = MigrationInfo {
        migrated: false,
        from_version: current_version,
        to_version: DEFAULT_SCHEMA_VERSION,
        steps: Vec::new(),
    };

    if current_version >= DEFAULT_SCHEMA_VERSION {
        return Ok(info);
    }

    let mut version = current_version;

    // v1 → v2: add `ou` column
    if version == 1 {
        conn.execute_batch(
            "ALTER TABLE config ADD COLUMN ou TEXT;
             UPDATE config SET schema_version = 2 WHERE id = 1;",
        )
        .map_err(|e| OpcaError::SchemaMigration(format!("v1→v2: {e}")))?;
        version = 2;
        info.steps.push(MigrationStep { to: 2, ok: true });
    }

    // v2 → v3: add storage location columns
    if version == 2 {
        conn.execute_batch(
            "ALTER TABLE config ADD COLUMN ca_public_store TEXT;
             ALTER TABLE config ADD COLUMN ca_private_store TEXT;
             ALTER TABLE config ADD COLUMN ca_backup_store TEXT;
             UPDATE config SET schema_version = 3 WHERE id = 1;",
        )
        .map_err(|e| OpcaError::SchemaMigration(format!("v2→v3: {e}")))?;
        version = 3;
        info.steps.push(MigrationStep { to: 3, ok: true });
    }

    // v3 → v4: add `issuer` to certificate_authority
    if version == 3 {
        conn.execute_batch(
            "ALTER TABLE certificate_authority ADD COLUMN issuer TEXT;
             UPDATE config SET schema_version = 4 WHERE id = 1;",
        )
        .map_err(|e| OpcaError::SchemaMigration(format!("v3→v4: {e}")))?;
        version = 4;
        info.steps.push(MigrationStep { to: 4, ok: true });
    }

    // v4 → v5: create CSR table (v5-era schema, without csr_pem)
    if version == 4 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS csr (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cn TEXT,
                title TEXT,
                csr_type TEXT,
                email TEXT,
                subject TEXT,
                status TEXT,
                created_date TEXT
            );
            UPDATE config SET schema_version = 5 WHERE id = 1;",
        )
        .map_err(|e| OpcaError::SchemaMigration(format!("v4→v5: {e}")))?;
        version = 5;
        info.steps.push(MigrationStep { to: 5, ok: true });
    }

    // v5 → v6: create external_certificate table, migrate issuer-bearing rows,
    //          drop issuer column from certificate_authority
    if version == 5 {
        // Create external_certificate (v6-era schema, without v7 metadata columns)
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS external_certificate (
                serial TEXT PRIMARY KEY,
                cn TEXT,
                title TEXT,
                status TEXT,
                expiry_date TEXT,
                subject TEXT,
                issuer TEXT,
                issuer_subject TEXT,
                import_date TEXT
            );",
        )
        .map_err(|e| OpcaError::SchemaMigration(format!("v5→v6 create table: {e}")))?;

        // Migrate external certs (those with issuer set)
        let import_ts = datetime::now_utc_str(DateTimeFormat::Openssl);
        conn.execute(
            "INSERT INTO external_certificate
                (serial, cn, title, status, expiry_date, subject, issuer, issuer_subject, import_date)
             SELECT serial, cn, 'EXT_' || cn, status, expiry_date, subject, issuer, issuer, ?1
             FROM certificate_authority
             WHERE issuer IS NOT NULL",
            [&import_ts],
        )
        .map_err(|e| OpcaError::SchemaMigration(format!("v5→v6 migrate rows: {e}")))?;

        conn.execute_batch(
            "DELETE FROM certificate_authority WHERE issuer IS NOT NULL;
             ALTER TABLE certificate_authority DROP COLUMN issuer;
             UPDATE config SET schema_version = 6 WHERE id = 1;",
        )
        .map_err(|e| OpcaError::SchemaMigration(format!("v5→v6 cleanup: {e}")))?;

        version = 6;
        info.steps.push(MigrationStep { to: 6, ok: true });
    }

    // v6 → v7: add metadata columns, csr_pem, new tables
    if version == 6 {
        conn.execute_batch(
            // certificate_authority: add metadata columns
            "ALTER TABLE certificate_authority ADD COLUMN cert_type TEXT;
             ALTER TABLE certificate_authority ADD COLUMN not_before TEXT;
             ALTER TABLE certificate_authority ADD COLUMN key_type TEXT;
             ALTER TABLE certificate_authority ADD COLUMN key_size INTEGER;
             ALTER TABLE certificate_authority ADD COLUMN issuer TEXT;
             ALTER TABLE certificate_authority ADD COLUMN san TEXT;

             ALTER TABLE external_certificate ADD COLUMN cert_type TEXT DEFAULT 'external';
             ALTER TABLE external_certificate ADD COLUMN not_before TEXT;
             ALTER TABLE external_certificate ADD COLUMN key_type TEXT;
             ALTER TABLE external_certificate ADD COLUMN key_size INTEGER;
             ALTER TABLE external_certificate ADD COLUMN san TEXT;

             ALTER TABLE csr ADD COLUMN csr_pem TEXT;

             UPDATE config SET schema_version = 7 WHERE id = 1;",
        )
        .map_err(|e| OpcaError::SchemaMigration(format!("v6→v7 alter tables: {e}")))?;

        // New tables
        conn.execute_batch(CREATE_CRL_METADATA_TABLE)
            .map_err(|e| OpcaError::SchemaMigration(format!("v6→v7 crl_metadata: {e}")))?;
        conn.execute_batch(CREATE_OPENVPN_TEMPLATE_TABLE)
            .map_err(|e| OpcaError::SchemaMigration(format!("v6→v7 openvpn_template: {e}")))?;
        conn.execute_batch(CREATE_OPENVPN_PROFILE_TABLE)
            .map_err(|e| OpcaError::SchemaMigration(format!("v6→v7 openvpn_profile: {e}")))?;

        version = 7;
        info.steps.push(MigrationStep { to: 7, ok: true });
    }

    // v7 → v8: add audit trail for ignored certificates
    if version == 7 {
        conn.execute_batch(
            "ALTER TABLE certificate_authority ADD COLUMN ignored_at TEXT;
             ALTER TABLE certificate_authority ADD COLUMN ignored_by TEXT;
             ALTER TABLE certificate_authority ADD COLUMN ignored_reason TEXT;
             ALTER TABLE certificate_authority ADD COLUMN ignored_note TEXT;
             UPDATE config SET schema_version = 8 WHERE id = 1;",
        )
        .map_err(|e| OpcaError::SchemaMigration(format!("v7→v8: {e}")))?;

        version = 8;
        let _ = version; // suppress unused warning
        info.steps.push(MigrationStep { to: 8, ok: true });
    }

    info.migrated = true;
    Ok(info)
}
