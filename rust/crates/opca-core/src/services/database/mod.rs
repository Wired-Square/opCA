mod iterdump;
pub mod models;
mod schema;

pub use models::*;
pub use schema::DEFAULT_SCHEMA_VERSION;

use std::collections::HashSet;
use std::time::Duration;

use chrono::Utc;
use rusqlite::Connection;

use crate::error::OpcaError;
use crate::utils::datetime::{self, DateTimeFormat};

/// Critical expiry warning window in days.
const EXPIRY_WARNING_DAYS: i64 = 30;

/// Caution expiry warning window in days (6 months).
const EXPIRY_CAUTION_DAYS: i64 = 183;

// ---------------------------------------------------------------------------
// Main struct
// ---------------------------------------------------------------------------

/// In-memory SQLite database for Certificate Authority operations.
///
/// Tracks all issued certificates, external certificates, CSRs, CRL metadata,
/// OpenVPN templates/profiles, and CA configuration. Supports schema versioning
/// with automatic migrations from v1 through v7.
pub struct CertificateAuthorityDB {
    conn: Connection,
    dirty: bool,
    pub download_fingerprint: Option<String>,

    // Status sets populated by `process_ca_database`
    pub certs_expired: HashSet<String>,
    pub certs_expires_soon: HashSet<String>,
    pub certs_expires_warning: HashSet<String>,
    pub certs_revoked: HashSet<String>,
    pub certs_valid: HashSet<String>,
    pub ext_certs_expired: HashSet<String>,
    pub ext_certs_expires_soon: HashSet<String>,
    pub ext_certs_expires_warning: HashSet<String>,
    pub ext_certs_valid: HashSet<String>,
}

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

impl CertificateAuthorityDB {
    /// Create a fresh database with the given configuration.
    pub fn new(config: &CaConfig) -> Result<Self, OpcaError> {
        let conn = Connection::open_in_memory()?;

        conn.execute_batch(schema::CREATE_CONFIG_TABLE)?;
        Self::insert_config(&conn, config)?;
        conn.execute_batch(schema::CREATE_CA_TABLE)?;
        conn.execute_batch(schema::CREATE_CSR_TABLE)?;
        conn.execute_batch(schema::CREATE_EXTERNAL_CERT_TABLE)?;
        conn.execute_batch(schema::CREATE_CRL_METADATA_TABLE)?;
        conn.execute_batch(schema::CREATE_OPENVPN_TEMPLATE_TABLE)?;
        conn.execute_batch(schema::CREATE_OPENVPN_PROFILE_TABLE)?;
        Self::create_indexes(&conn)?;

        Ok(Self {
            conn,
            dirty: true,
            download_fingerprint: None,
            certs_expired: HashSet::new(),
            certs_expires_soon: HashSet::new(),
            certs_expires_warning: HashSet::new(),
            certs_revoked: HashSet::new(),
            certs_valid: HashSet::new(),
            ext_certs_expired: HashSet::new(),
            ext_certs_expires_soon: HashSet::new(),
            ext_certs_expires_warning: HashSet::new(),
            ext_certs_valid: HashSet::new(),
        })
    }

    /// Import an existing database from a SQL text dump.
    ///
    /// Automatically runs schema migrations if the dump is from an older version.
    pub fn from_sql_dump(data: &str) -> Result<(Self, MigrationInfo), OpcaError> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(data)?;

        // Read current schema version
        let version: i64 = conn.query_row(
            "SELECT schema_version FROM config LIMIT 1",
            [],
            |row| row.get(0),
        )?;

        let info = schema::migrate(&conn, version)?;
        Self::create_indexes(&conn)?;

        let db = Self {
            conn,
            dirty: true,
            download_fingerprint: None,
            certs_expired: HashSet::new(),
            certs_expires_soon: HashSet::new(),
            certs_expires_warning: HashSet::new(),
            certs_revoked: HashSet::new(),
            certs_valid: HashSet::new(),
            ext_certs_expired: HashSet::new(),
            ext_certs_expires_soon: HashSet::new(),
            ext_certs_expires_warning: HashSet::new(),
            ext_certs_valid: HashSet::new(),
        };

        Ok((db, info))
    }

    /// Insert the initial config row (id=1) into the config table.
    fn insert_config(conn: &Connection, config: &CaConfig) -> Result<(), OpcaError> {
        let mut columns = vec!["id", "schema_version"];
        let mut values: Vec<Box<dyn rusqlite::types::ToSql>> = vec![
            Box::new(1i64),
            Box::new(DEFAULT_SCHEMA_VERSION),
        ];

        macro_rules! push_field {
            ($field:ident, $col:expr, str) => {
                columns.push($col);
                values.push(Box::new(
                    config.$field.as_deref().unwrap_or("").to_string(),
                ));
            };
            ($field:ident, $col:expr, serial) => {
                columns.push($col);
                values.push(Box::new(
                    config.$field.map(|v| v.to_string()).unwrap_or_default(),
                ));
            };
            ($field:ident, $col:expr, int) => {
                columns.push($col);
                values.push(Box::new(config.$field));
            };
        }

        push_field!(next_serial, "next_serial", serial);
        push_field!(next_crl_serial, "next_crl_serial", serial);
        push_field!(org, "org", str);
        push_field!(ou, "ou", str);
        push_field!(email, "email", str);
        push_field!(city, "city", str);
        push_field!(state, "state", str);
        push_field!(country, "country", str);
        push_field!(ca_url, "ca_url", str);
        push_field!(crl_url, "crl_url", str);
        push_field!(days, "days", int);
        push_field!(crl_days, "crl_days", int);
        push_field!(ca_public_store, "ca_public_store", str);
        push_field!(ca_private_store, "ca_private_store", str);
        push_field!(ca_backup_store, "ca_backup_store", str);

        let col_list = columns.join(", ");
        let placeholders = (0..columns.len())
            .map(|i| format!("?{}", i + 1))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!("INSERT INTO config ({col_list}) VALUES ({placeholders})");

        let params: Vec<&dyn rusqlite::types::ToSql> = values.iter().map(|v| v.as_ref()).collect();
        conn.execute(&sql, params.as_slice())?;

        Ok(())
    }

    fn create_indexes(conn: &Connection) -> Result<(), OpcaError> {
        for idx_sql in schema::CREATE_INDEXES {
            conn.execute_batch(idx_sql)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Config methods
// ---------------------------------------------------------------------------

impl CertificateAuthorityDB {
    /// Retrieve all CA configuration attributes.
    pub fn get_config(&self) -> Result<CaConfig, OpcaError> {
        let mut stmt = self.conn.prepare(
            "SELECT next_serial, next_crl_serial, org, ou, email, city, state, country,
                    ca_url, crl_url, days, crl_days, schema_version,
                    ca_public_store, ca_private_store, ca_backup_store
             FROM config LIMIT 1",
        )?;

        let config = stmt.query_row([], |row| {
            // Serial fields are stored as TEXT — parse to i64
            let next_serial: Option<String> = row.get(0)?;
            let next_crl_serial: Option<String> = row.get(1)?;

            Ok(CaConfig {
                cn: None,
                ca_days: None,
                next_serial: next_serial
                    .as_deref()
                    .and_then(|s| s.trim().parse::<i64>().ok()),
                next_crl_serial: next_crl_serial
                    .as_deref()
                    .and_then(|s| s.trim().parse::<i64>().ok()),
                org: row.get(2)?,
                ou: row.get(3)?,
                email: row.get(4)?,
                city: row.get(5)?,
                state: row.get(6)?,
                country: row.get(7)?,
                ca_url: row.get(8)?,
                crl_url: row.get(9)?,
                days: row.get(10)?,
                crl_days: row.get(11)?,
                schema_version: row.get(12)?,
                ca_public_store: row.get(13)?,
                ca_private_store: row.get(14)?,
                ca_backup_store: row.get(15)?,
            })
        })?;

        Ok(config)
    }

    /// Update the config table with the provided values.
    ///
    /// Only known config attributes are written; unknown keys are silently ignored.
    pub fn update_config(&self, updates: &CaConfig) -> Result<(), OpcaError> {
        let mut set_clauses = Vec::new();
        let mut values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        macro_rules! maybe_update {
            ($field:ident, $col:expr, str) => {
                if let Some(ref v) = updates.$field {
                    set_clauses.push(format!("{} = ?", $col));
                    values.push(Box::new(v.clone()));
                }
            };
            ($field:ident, $col:expr, serial) => {
                if let Some(v) = updates.$field {
                    set_clauses.push(format!("{} = ?", $col));
                    values.push(Box::new(v.to_string()));
                }
            };
            ($field:ident, $col:expr, int) => {
                if let Some(v) = updates.$field {
                    set_clauses.push(format!("{} = ?", $col));
                    values.push(Box::new(v));
                }
            };
        }

        maybe_update!(next_serial, "next_serial", serial);
        maybe_update!(next_crl_serial, "next_crl_serial", serial);
        maybe_update!(org, "org", str);
        maybe_update!(ou, "ou", str);
        maybe_update!(email, "email", str);
        maybe_update!(city, "city", str);
        maybe_update!(state, "state", str);
        maybe_update!(country, "country", str);
        maybe_update!(ca_url, "ca_url", str);
        maybe_update!(crl_url, "crl_url", str);
        maybe_update!(days, "days", int);
        maybe_update!(crl_days, "crl_days", int);
        maybe_update!(schema_version, "schema_version", int);
        maybe_update!(ca_public_store, "ca_public_store", str);
        maybe_update!(ca_private_store, "ca_private_store", str);
        maybe_update!(ca_backup_store, "ca_backup_store", str);

        if set_clauses.is_empty() {
            return Ok(());
        }

        let sql = format!("UPDATE config SET {} WHERE id = 1", set_clauses.join(", "));
        let params: Vec<&dyn rusqlite::types::ToSql> = values.iter().map(|v| v.as_ref()).collect();
        self.conn.execute(&sql, params.as_slice())?;

        Ok(())
    }

    /// Get the current serial number and increment the counter.
    ///
    /// If `serial_number` is provided and is greater than the current counter,
    /// the counter jumps to that value before incrementing.
    ///
    /// Returns the current serial number (before increment).
    pub fn increment_serial(
        &mut self,
        serial_type: SerialType,
        serial_number: Option<i64>,
    ) -> Result<i64, OpcaError> {
        let column_name = match serial_type {
            SerialType::Cert => "next_serial",
            SerialType::Crl => "next_crl_serial",
        };

        let raw: Option<String> = self.conn.query_row(
            &format!("SELECT {column_name} FROM config LIMIT 1"),
            [],
            |row| row.get(0),
        )?;

        let mut current_value = raw
            .as_deref()
            .and_then(|s| {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    trimmed.parse::<i64>().ok()
                }
            })
            .unwrap_or(0);

        // Bump forward if caller supplies an explicit serial
        if let Some(sn) = serial_number {
            if sn > current_value {
                current_value = sn;
            }
        }

        let next_serial = current_value + 1;
        self.conn.execute(
            &format!("UPDATE config SET {column_name} = ? WHERE id = 1"),
            [next_serial.to_string()],
        )?;

        self.dirty = true;
        Ok(current_value)
    }
}

// ---------------------------------------------------------------------------
// Certificate CRUD
// ---------------------------------------------------------------------------

impl CertificateAuthorityDB {
    /// Add a certificate record to the database.
    pub fn add_cert(&mut self, record: &CertRecord) -> Result<(), OpcaError> {
        self.conn.execute(
            "INSERT INTO certificate_authority
                (serial, cn, title, status, expiry_date, revocation_date, subject,
                 cert_type, not_before, key_type, key_size, issuer, san)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            rusqlite::params![
                record.serial,
                record.cn,
                record.title,
                record.status,
                record.expiry_date,
                record.revocation_date,
                record.subject,
                record.cert_type,
                record.not_before,
                record.key_type,
                record.key_size,
                record.issuer,
                record.san,
            ],
        )?;
        self.dirty = true;
        Ok(())
    }

    /// Update an existing certificate record by serial number.
    pub fn update_cert(&mut self, record: &CertRecord) -> Result<(), OpcaError> {
        let rows = self.conn.execute(
            "UPDATE certificate_authority SET
                cn = ?1, title = ?2, status = ?3, expiry_date = ?4,
                revocation_date = ?5, subject = ?6, cert_type = ?7,
                not_before = ?8, key_type = ?9, key_size = ?10,
                issuer = ?11, san = ?12
             WHERE serial = ?13",
            rusqlite::params![
                record.cn,
                record.title,
                record.status,
                record.expiry_date,
                record.revocation_date,
                record.subject,
                record.cert_type,
                record.not_before,
                record.key_type,
                record.key_size,
                record.issuer,
                record.san,
                record.serial,
            ],
        )?;

        if rows == 0 {
            return Err(OpcaError::Database(format!(
                "No certificate found with serial number {}.",
                record.serial
            )));
        }

        self.dirty = true;
        Ok(())
    }

    /// Search for a certificate by serial, CN, or title.
    pub fn query_cert(
        &self,
        lookup: &CertLookup,
        valid_only: bool,
    ) -> Result<Option<CertRecord>, OpcaError> {
        let (where_col, value) = match lookup {
            CertLookup::Serial(s) => ("serial", s.clone()),
            CertLookup::Cn(s) => ("cn", s.clone()),
            CertLookup::Title(s) => ("title", s.clone()),
        };

        let valid_clause = if valid_only {
            " AND status = 'Valid'"
        } else {
            ""
        };

        let sql = format!(
            "SELECT serial, cn, title, status, expiry_date, revocation_date, subject,
                    cert_type, not_before, key_type, key_size, issuer, san
             FROM certificate_authority WHERE {where_col} = ?1{valid_clause}"
        );

        let mut stmt = self.conn.prepare(&sql)?;
        let result = stmt.query_row([&value], |row| {
            Ok(CertRecord {
                serial: row.get(0)?,
                cn: row.get(1)?,
                title: row.get(2)?,
                status: row.get(3)?,
                expiry_date: row.get(4)?,
                revocation_date: row.get(5)?,
                subject: row.get(6)?,
                cert_type: row.get(7)?,
                not_before: row.get(8)?,
                key_type: row.get(9)?,
                key_size: row.get(10)?,
                issuer: row.get(11)?,
                san: row.get(12)?,
            })
        });

        match result {
            Ok(record) => Ok(Some(record)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Count the number of CA-issued certificates.
    pub fn count_certs(&self) -> Result<i64, OpcaError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM certificate_authority",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Return all CA-issued certificate records.
    pub fn query_all_certs(&self) -> Result<Vec<CertRecord>, OpcaError> {
        let mut stmt = self.conn.prepare(
            "SELECT serial, cn, title, status, expiry_date, revocation_date, subject,
                    cert_type, not_before, key_type, key_size, issuer, san
             FROM certificate_authority ORDER BY CAST(serial AS INTEGER)"
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(CertRecord {
                serial: row.get(0)?,
                cn: row.get(1)?,
                title: row.get(2)?,
                status: row.get(3)?,
                expiry_date: row.get(4)?,
                revocation_date: row.get(5)?,
                subject: row.get(6)?,
                cert_type: row.get(7)?,
                not_before: row.get(8)?,
                key_type: row.get(9)?,
                key_size: row.get(10)?,
                issuer: row.get(11)?,
                san: row.get(12)?,
            })
        })?;

        let mut certs = Vec::new();
        for row in rows {
            certs.push(row?);
        }
        Ok(certs)
    }
}

// ---------------------------------------------------------------------------
// External certificate CRUD
// ---------------------------------------------------------------------------

impl CertificateAuthorityDB {
    /// Add an external certificate record.
    pub fn add_external_cert(&mut self, record: &ExternalCertRecord) -> Result<(), OpcaError> {
        self.conn.execute(
            "INSERT INTO external_certificate
                (serial, cn, title, status, expiry_date, subject, issuer, issuer_subject,
                 import_date, cert_type, not_before, key_type, key_size, san)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            rusqlite::params![
                record.serial,
                record.cn,
                record.title,
                record.status,
                record.expiry_date,
                record.subject,
                record.issuer,
                record.issuer_subject,
                record.import_date,
                record.cert_type,
                record.not_before,
                record.key_type,
                record.key_size,
                record.san,
            ],
        )?;
        self.dirty = true;
        Ok(())
    }

    /// Update an existing external certificate record by serial.
    pub fn update_external_cert(&self, record: &ExternalCertRecord) -> Result<(), OpcaError> {
        let rows = self.conn.execute(
            "UPDATE external_certificate SET
                cn = ?1, title = ?2, status = ?3, expiry_date = ?4,
                subject = ?5, issuer = ?6, issuer_subject = ?7,
                import_date = ?8, cert_type = ?9, not_before = ?10,
                key_type = ?11, key_size = ?12, san = ?13
             WHERE serial = ?14",
            rusqlite::params![
                record.cn,
                record.title,
                record.status,
                record.expiry_date,
                record.subject,
                record.issuer,
                record.issuer_subject,
                record.import_date,
                record.cert_type,
                record.not_before,
                record.key_type,
                record.key_size,
                record.san,
                record.serial,
            ],
        )?;

        if rows == 0 {
            return Err(OpcaError::Database(format!(
                "No external certificate found with serial number {}.",
                record.serial
            )));
        }

        Ok(())
    }

    /// Search for an external certificate by serial, CN, or title.
    pub fn query_external_cert(
        &self,
        lookup: &CertLookup,
        valid_only: bool,
    ) -> Result<Option<ExternalCertRecord>, OpcaError> {
        let (where_col, value) = match lookup {
            CertLookup::Serial(s) => ("serial", s.clone()),
            CertLookup::Cn(s) => ("cn", s.clone()),
            CertLookup::Title(s) => ("title", s.clone()),
        };

        let valid_clause = if valid_only {
            " AND status = 'Valid'"
        } else {
            ""
        };

        let sql = format!(
            "SELECT serial, cn, title, status, expiry_date, subject, issuer, issuer_subject,
                    import_date, cert_type, not_before, key_type, key_size, san
             FROM external_certificate WHERE {where_col} = ?1{valid_clause}"
        );

        let mut stmt = self.conn.prepare(&sql)?;
        let result = stmt.query_row([&value], Self::row_to_external_cert);

        match result {
            Ok(record) => Ok(Some(record)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Return all external certificates, optionally filtered by status.
    pub fn query_all_external_certs(
        &self,
        status: Option<&str>,
    ) -> Result<Vec<ExternalCertRecord>, OpcaError> {
        let (sql, params): (String, Vec<Box<dyn rusqlite::types::ToSql>>) = match status {
            Some(s) => (
                "SELECT serial, cn, title, status, expiry_date, subject, issuer, issuer_subject,
                        import_date, cert_type, not_before, key_type, key_size, san
                 FROM external_certificate WHERE status = ?1 ORDER BY serial"
                    .to_string(),
                vec![Box::new(s.to_string())],
            ),
            None => (
                "SELECT serial, cn, title, status, expiry_date, subject, issuer, issuer_subject,
                        import_date, cert_type, not_before, key_type, key_size, san
                 FROM external_certificate ORDER BY serial"
                    .to_string(),
                vec![],
            ),
        };

        let mut stmt = self.conn.prepare(&sql)?;
        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|v| v.as_ref()).collect();
        let rows = stmt.query_map(param_refs.as_slice(), Self::row_to_external_cert)?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Count external certificates.
    pub fn count_external_certs(&self) -> Result<i64, OpcaError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM external_certificate",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    fn row_to_external_cert(row: &rusqlite::Row<'_>) -> rusqlite::Result<ExternalCertRecord> {
        Ok(ExternalCertRecord {
            serial: row.get(0)?,
            cn: row.get(1)?,
            title: row.get(2)?,
            status: row.get(3)?,
            expiry_date: row.get(4)?,
            subject: row.get(5)?,
            issuer: row.get(6)?,
            issuer_subject: row.get(7)?,
            import_date: row.get(8)?,
            cert_type: row.get(9)?,
            not_before: row.get(10)?,
            key_type: row.get(11)?,
            key_size: row.get(12)?,
            san: row.get(13)?,
        })
    }
}

// ---------------------------------------------------------------------------
// CSR CRUD
// ---------------------------------------------------------------------------

impl CertificateAuthorityDB {
    /// Add a CSR record to the database.
    pub fn add_csr(&self, record: &CsrRecord) -> Result<(), OpcaError> {
        self.conn.execute(
            "INSERT INTO csr (cn, title, csr_type, email, subject, status, created_date, csr_pem)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                record.cn,
                record.title,
                record.csr_type,
                record.email,
                record.subject,
                record.status,
                record.created_date,
                record.csr_pem,
            ],
        )?;
        Ok(())
    }

    /// Update an existing CSR record, identified by `id` or `cn`.
    pub fn update_csr(&self, record: &CsrRecord) -> Result<bool, OpcaError> {
        let (where_col, where_val): (&str, Box<dyn rusqlite::types::ToSql>) =
            if let Some(id) = record.id {
                ("id", Box::new(id))
            } else if let Some(ref cn) = record.cn {
                ("cn", Box::new(cn.clone()))
            } else {
                return Err(OpcaError::Database(
                    "Either 'id' or 'cn' must be provided to update a CSR.".to_string(),
                ));
            };

        // Build SET clause from non-identifier fields
        let mut set_clauses = Vec::new();
        let mut values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        macro_rules! maybe_set {
            ($field:ident, $col:expr) => {
                if let Some(ref v) = record.$field {
                    set_clauses.push(format!("{} = ?", $col));
                    values.push(Box::new(v.clone()));
                }
            };
        }

        // Only set fields that are present (skip the identifier field)
        if where_col != "cn" {
            maybe_set!(cn, "cn");
        }
        maybe_set!(title, "title");
        maybe_set!(csr_type, "csr_type");
        maybe_set!(email, "email");
        maybe_set!(subject, "subject");
        maybe_set!(status, "status");
        maybe_set!(created_date, "created_date");
        maybe_set!(csr_pem, "csr_pem");

        if set_clauses.is_empty() {
            return Ok(false);
        }

        values.push(where_val);
        let sql = format!(
            "UPDATE csr SET {} WHERE {} = ?",
            set_clauses.join(", "),
            where_col
        );
        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            values.iter().map(|v| v.as_ref()).collect();
        let rows = self.conn.execute(&sql, param_refs.as_slice())?;

        Ok(rows > 0)
    }

    /// Search for a CSR by id or CN.
    pub fn query_csr(&self, lookup: &CsrLookup) -> Result<Option<CsrRecord>, OpcaError> {
        let (sql, param): (&str, Box<dyn rusqlite::types::ToSql>) = match lookup {
            CsrLookup::Id(id) => ("SELECT * FROM csr WHERE id = ?1", Box::new(*id)),
            CsrLookup::Cn(cn) => ("SELECT * FROM csr WHERE cn = ?1", Box::new(cn.clone())),
        };

        let mut stmt = self.conn.prepare(sql)?;
        let result = stmt.query_row([param.as_ref()], |row| {
            Ok(CsrRecord {
                id: row.get(0)?,
                cn: row.get(1)?,
                title: row.get(2)?,
                csr_type: row.get(3)?,
                email: row.get(4)?,
                subject: row.get(5)?,
                status: row.get(6)?,
                created_date: row.get(7)?,
                csr_pem: row.get(8)?,
            })
        });

        match result {
            Ok(record) => Ok(Some(record)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Return all CSR records, optionally filtered by status.
    pub fn query_all_csrs(&self, status: Option<&str>) -> Result<Vec<CsrRecord>, OpcaError> {
        let (sql, params): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) = match status {
            Some(s) => (
                "SELECT * FROM csr WHERE status = ?1 ORDER BY id",
                vec![Box::new(s.to_string())],
            ),
            None => ("SELECT * FROM csr ORDER BY id", vec![]),
        };

        let mut stmt = self.conn.prepare(sql)?;
        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|v| v.as_ref()).collect();
        let rows = stmt.query_map(param_refs.as_slice(), |row| {
            Ok(CsrRecord {
                id: row.get(0)?,
                cn: row.get(1)?,
                title: row.get(2)?,
                csr_type: row.get(3)?,
                email: row.get(4)?,
                subject: row.get(5)?,
                status: row.get(6)?,
                created_date: row.get(7)?,
                csr_pem: row.get(8)?,
            })
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }
}

// ---------------------------------------------------------------------------
// CRL metadata
// ---------------------------------------------------------------------------

impl CertificateAuthorityDB {
    /// Insert or replace CRL metadata (singleton row, id=1).
    pub fn upsert_crl_metadata(&self, metadata: &CrlMetadata) -> Result<(), OpcaError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO crl_metadata
                (id, issuer, last_update, next_update, crl_number, revoked_count, revoked_json)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                metadata.issuer,
                metadata.last_update,
                metadata.next_update,
                metadata.crl_number,
                metadata.revoked_count,
                metadata.revoked_json,
            ],
        )?;
        Ok(())
    }

    /// Return the cached CRL metadata, or `None` if not yet populated.
    pub fn get_crl_metadata(&self) -> Result<Option<CrlMetadata>, OpcaError> {
        let mut stmt = self
            .conn
            .prepare("SELECT issuer, last_update, next_update, crl_number, revoked_count, revoked_json FROM crl_metadata WHERE id = 1")?;

        let result = stmt.query_row([], |row| {
            Ok(CrlMetadata {
                issuer: row.get(0)?,
                last_update: row.get(1)?,
                next_update: row.get(2)?,
                crl_number: row.get(3)?,
                revoked_count: row.get(4)?,
                revoked_json: row.get(5)?,
            })
        });

        match result {
            Ok(m) => Ok(Some(m)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// OpenVPN templates
// ---------------------------------------------------------------------------

impl CertificateAuthorityDB {
    /// Insert or update an OpenVPN template by name.
    pub fn upsert_openvpn_template(
        &self,
        name: &str,
        content: &str,
        updated_date: Option<&str>,
    ) -> Result<(), OpcaError> {
        let date = updated_date
            .map(|s| s.to_string())
            .unwrap_or_else(|| datetime::now_utc_str(DateTimeFormat::Openssl));

        self.conn.execute(
            "INSERT INTO openvpn_template (name, content, updated_date)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(name) DO UPDATE SET content = excluded.content, updated_date = excluded.updated_date",
            rusqlite::params![name, content, date],
        )?;
        Ok(())
    }

    /// Return a single OpenVPN template by name.
    pub fn get_openvpn_template(&self, name: &str) -> Result<Option<OpenVpnTemplate>, OpcaError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, content, updated_date FROM openvpn_template WHERE name = ?1")?;

        let result = stmt.query_row([name], |row| {
            Ok(OpenVpnTemplate {
                id: row.get(0)?,
                name: row.get(1)?,
                content: row.get(2)?,
                updated_date: row.get(3)?,
            })
        });

        match result {
            Ok(t) => Ok(Some(t)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Return all OpenVPN templates ordered by name.
    pub fn query_all_openvpn_templates(&self) -> Result<Vec<OpenVpnTemplate>, OpcaError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, content, updated_date FROM openvpn_template ORDER BY name")?;

        let rows = stmt.query_map([], |row| {
            Ok(OpenVpnTemplate {
                id: row.get(0)?,
                name: row.get(1)?,
                content: row.get(2)?,
                updated_date: row.get(3)?,
            })
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Delete an OpenVPN template by name.
    pub fn delete_openvpn_template(&self, name: &str) -> Result<bool, OpcaError> {
        let rows = self
            .conn
            .execute("DELETE FROM openvpn_template WHERE name = ?1", [name])?;
        Ok(rows > 0)
    }
}

// ---------------------------------------------------------------------------
// OpenVPN profiles
// ---------------------------------------------------------------------------

impl CertificateAuthorityDB {
    /// Add an OpenVPN profile registry entry.
    pub fn add_openvpn_profile(&self, profile: &OpenVpnProfile) -> Result<(), OpcaError> {
        self.conn.execute(
            "INSERT INTO openvpn_profile (cn, title, created_date, template)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                profile.cn,
                profile.title,
                profile.created_date,
                profile.template,
            ],
        )?;
        Ok(())
    }

    /// Return all OpenVPN profiles ordered by CN.
    pub fn query_all_openvpn_profiles(&self) -> Result<Vec<OpenVpnProfile>, OpcaError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, cn, title, created_date, template FROM openvpn_profile ORDER BY cn",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(OpenVpnProfile {
                id: row.get(0)?,
                cn: row.get(1)?,
                title: row.get(2)?,
                created_date: row.get(3)?,
                template: row.get(4)?,
            })
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Delete an OpenVPN profile by title.
    pub fn delete_openvpn_profile(&self, title: &str) -> Result<bool, OpcaError> {
        let rows = self
            .conn
            .execute("DELETE FROM openvpn_profile WHERE title = ?1", [title])?;
        Ok(rows > 0)
    }
}

// ---------------------------------------------------------------------------
// Status processing
// ---------------------------------------------------------------------------

impl CertificateAuthorityDB {
    /// Process the certificate database to update certificate states.
    ///
    /// Scans all certificates and:
    /// 1. Updates status based on expiry dates (Valid → Expired)
    /// 2. Optionally revokes a certificate by serial number
    /// 3. Categorises certificates into status sets
    ///
    /// Returns `true` if any database records were modified.
    pub fn process_ca_database(
        &mut self,
        revoke_serial: Option<&str>,
    ) -> Result<bool, OpcaError> {
        if !self.dirty && revoke_serial.is_none() {
            return Ok(false);
        }

        let mut db_changed = false;
        self.certs_expired.clear();
        self.certs_expires_soon.clear();
        self.certs_expires_warning.clear();
        self.certs_revoked.clear();
        self.certs_valid.clear();
        self.ext_certs_expired.clear();
        self.ext_certs_expires_soon.clear();
        self.ext_certs_expires_warning.clear();
        self.ext_certs_valid.clear();

        let now = Utc::now().naive_utc();
        let warning_boundary =
            now + chrono::Duration::days(EXPIRY_WARNING_DAYS);
        let caution_boundary =
            now + chrono::Duration::days(EXPIRY_CAUTION_DAYS);

        // Process CA-issued certificates
        let certs = self.fetch_all_ca_certs()?;
        for mut cert in certs {
            let mut cert_changed = false;

            let expiry_str = match cert.expiry_date.as_deref() {
                Some(s) if !s.is_empty() => s,
                _ => continue,
            };

            let expiry_date = match datetime::parse_datetime(expiry_str, DateTimeFormat::Openssl) {
                Ok(dt) => dt.naive_utc(),
                Err(_) => continue,
            };

            let expired = now > expiry_date;
            let expires_soon = warning_boundary > expiry_date;
            let mut revoked = cert.revocation_date.as_ref().is_some_and(|rd| !rd.is_empty())
                || cert.status.as_deref() == Some("Revoked");

            if let Some(rev_serial) = revoke_serial {
                if !expired && !revoked && rev_serial == cert.serial {
                    revoked = true;
                    cert_changed = true;
                    db_changed = true;
                    cert.revocation_date =
                        Some(datetime::now_utc_str(DateTimeFormat::Openssl));
                }
            }

            let expires_warning = caution_boundary > expiry_date;

            if expired {
                if cert.status.as_deref() != Some("Expired") {
                    cert_changed = true;
                    db_changed = true;
                    cert.status = Some("Expired".to_string());
                }
                self.certs_expired.insert(cert.serial.clone());
            } else if revoked {
                if cert.status.as_deref() != Some("Revoked") {
                    cert_changed = true;
                    db_changed = true;
                    cert.status = Some("Revoked".to_string());
                }
                self.certs_revoked.insert(cert.serial.clone());
            } else if expires_soon {
                self.certs_expires_soon.insert(cert.serial.clone());
                self.certs_expires_warning.insert(cert.serial.clone());
            } else if expires_warning {
                self.certs_expires_warning.insert(cert.serial.clone());
            } else {
                self.certs_valid.insert(cert.serial.clone());
            }

            if cert_changed {
                self.update_cert(&cert)?;
            }
        }

        // Process external certificates (no revocation)
        let ext_certs = self.fetch_all_external_certs()?;
        for mut ext in ext_certs {
            let mut ext_changed = false;

            let expiry_str = match ext.expiry_date.as_deref() {
                Some(s) if !s.is_empty() => s,
                _ => continue,
            };

            let expiry_date = match datetime::parse_datetime(expiry_str, DateTimeFormat::Openssl) {
                Ok(dt) => dt.naive_utc(),
                Err(_) => continue,
            };

            let expired = now > expiry_date;
            let expires_soon = warning_boundary > expiry_date;
            let expires_warning = caution_boundary > expiry_date;

            if expired {
                if ext.status.as_deref() != Some("Expired") {
                    ext_changed = true;
                    db_changed = true;
                    ext.status = Some("Expired".to_string());
                }
                self.ext_certs_expired.insert(ext.serial.clone());
            } else if expires_soon {
                self.ext_certs_expires_soon.insert(ext.serial.clone());
                self.ext_certs_expires_warning.insert(ext.serial.clone());
            } else if expires_warning {
                self.ext_certs_expires_warning.insert(ext.serial.clone());
            } else {
                self.ext_certs_valid.insert(ext.serial.clone());
            }

            if ext_changed {
                self.update_external_cert(&ext)?;
            }
        }

        self.dirty = false;
        Ok(db_changed)
    }

    /// Fetch all rows from `certificate_authority` (internal helper).
    fn fetch_all_ca_certs(&self) -> Result<Vec<CertRecord>, OpcaError> {
        let mut stmt = self.conn.prepare(
            "SELECT serial, cn, title, status, expiry_date, revocation_date, subject,
                    cert_type, not_before, key_type, key_size, issuer, san
             FROM certificate_authority",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(CertRecord {
                serial: row.get(0)?,
                cn: row.get(1)?,
                title: row.get(2)?,
                status: row.get(3)?,
                expiry_date: row.get(4)?,
                revocation_date: row.get(5)?,
                subject: row.get(6)?,
                cert_type: row.get(7)?,
                not_before: row.get(8)?,
                key_type: row.get(9)?,
                key_size: row.get(10)?,
                issuer: row.get(11)?,
                san: row.get(12)?,
            })
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Fetch all rows from `external_certificate` (internal helper).
    fn fetch_all_external_certs(&self) -> Result<Vec<ExternalCertRecord>, OpcaError> {
        let mut stmt = self.conn.prepare(
            "SELECT serial, cn, title, status, expiry_date, subject, issuer, issuer_subject,
                    import_date, cert_type, not_before, key_type, key_size, san
             FROM external_certificate",
        )?;

        let rows = stmt.query_map([], Self::row_to_external_cert)?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

impl CertificateAuthorityDB {
    /// Export the entire database as SQL text (matching Python's `conn.iterdump()` format).
    pub fn export_database(&self) -> Result<Vec<u8>, OpcaError> {
        let sql_text = iterdump::iterdump(&self.conn)?;
        Ok(sql_text.into_bytes())
    }

    /// Export the in-memory database as a binary SQLite file.
    pub fn export_database_binary(&self) -> Result<Vec<u8>, OpcaError> {
        let tmp = tempfile::NamedTempFile::new()?;
        let mut dst = Connection::open(tmp.path())?;

        let backup = rusqlite::backup::Backup::new(&self.conn, &mut dst)?;
        backup.run_to_completion(5, Duration::from_millis(250), None)?;
        drop(backup);
        dst.close()
            .map_err(|(_, e)| OpcaError::Database(e.to_string()))?;

        let bytes = std::fs::read(tmp.path())?;
        Ok(bytes)
    }
}

// ---------------------------------------------------------------------------
// Lifecycle / state
// ---------------------------------------------------------------------------

impl CertificateAuthorityDB {
    /// Whether the database has been modified since the last `process_ca_database` call.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Close the database connection (consumes self).
    pub fn close(self) {
        let _ = self.conn.close();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
