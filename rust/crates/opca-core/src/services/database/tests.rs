use super::*;

/// Helper to create a fresh database with sensible defaults.
fn test_db() -> CertificateAuthorityDB {
    CertificateAuthorityDB::new(&CaConfig {
        next_serial: Some(100),
        next_crl_serial: Some(1),
        org: Some("Test Org".to_string()),
        ou: Some("Test OU".to_string()),
        email: Some("test@example.com".to_string()),
        city: Some("Sydney".to_string()),
        state: Some("NSW".to_string()),
        country: Some("AU".to_string()),
        ca_url: Some("https://ca.example.com".to_string()),
        crl_url: Some("https://crl.example.com".to_string()),
        days: Some(365),
        crl_days: Some(30),
        ..Default::default()
    })
    .expect("Failed to create test database")
}

/// Helper: make a CertRecord with defaults.
fn make_cert(serial: &str, cn: &str, expiry: &str) -> CertRecord {
    CertRecord {
        serial: serial.to_string(),
        cn: Some(cn.to_string()),
        title: Some(cn.to_string()),
        status: Some("Valid".to_string()),
        expiry_date: Some(expiry.to_string()),
        revocation_date: None,
        subject: Some(format!("/CN={cn}")),
        cert_type: Some("server".to_string()),
        not_before: Some("20250101000000Z".to_string()),
        key_type: Some("RSA".to_string()),
        key_size: Some(2048),
        issuer: Some("Test CA".to_string()),
        san: None,
    }
}

// -----------------------------------------------------------------------
// Initialisation
// -----------------------------------------------------------------------

#[test]
fn test_new_creates_all_tables() {
    let db = test_db();
    // Verify we can query each table without error
    assert_eq!(db.count_certs().unwrap(), 0);
    assert_eq!(db.count_external_certs().unwrap(), 0);
    assert!(db.query_all_csrs(None).unwrap().is_empty());
    assert!(db.get_crl_metadata().unwrap().is_none());
    assert!(db.query_all_openvpn_templates().unwrap().is_empty());
    assert!(db.query_all_openvpn_profiles().unwrap().is_empty());
}

#[test]
fn test_new_sets_schema_version_7() {
    let db = test_db();
    let config = db.get_config().unwrap();
    assert_eq!(config.schema_version, Some(7));
}

#[test]
fn test_new_with_config_values() {
    let db = test_db();
    let config = db.get_config().unwrap();
    assert_eq!(config.next_serial, Some(100));
    assert_eq!(config.next_crl_serial, Some(1));
    assert_eq!(config.org.as_deref(), Some("Test Org"));
    assert_eq!(config.ou.as_deref(), Some("Test OU"));
    assert_eq!(config.email.as_deref(), Some("test@example.com"));
    assert_eq!(config.city.as_deref(), Some("Sydney"));
    assert_eq!(config.state.as_deref(), Some("NSW"));
    assert_eq!(config.country.as_deref(), Some("AU"));
    assert_eq!(config.days, Some(365));
    assert_eq!(config.crl_days, Some(30));
}

// -----------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------

#[test]
fn test_update_config() {
    let db = test_db();
    db.update_config(&CaConfig {
        org: Some("New Org".to_string()),
        days: Some(730),
        ..Default::default()
    })
    .unwrap();

    let config = db.get_config().unwrap();
    assert_eq!(config.org.as_deref(), Some("New Org"));
    assert_eq!(config.days, Some(730));
    // Unchanged fields stay as they were
    assert_eq!(config.city.as_deref(), Some("Sydney"));
}

#[test]
fn test_update_config_serial_conversion() {
    let db = test_db();
    db.update_config(&CaConfig {
        next_serial: Some(500),
        ..Default::default()
    })
    .unwrap();

    let config = db.get_config().unwrap();
    assert_eq!(config.next_serial, Some(500));
}

// -----------------------------------------------------------------------
// Serial numbers
// -----------------------------------------------------------------------

#[test]
fn test_increment_cert_serial() {
    let mut db = test_db();
    let serial = db.increment_serial(SerialType::Cert, None).unwrap();
    assert_eq!(serial, 100);

    let serial = db.increment_serial(SerialType::Cert, None).unwrap();
    assert_eq!(serial, 101);
}

#[test]
fn test_increment_crl_serial() {
    let mut db = test_db();
    let serial = db.increment_serial(SerialType::Crl, None).unwrap();
    assert_eq!(serial, 1);

    let serial = db.increment_serial(SerialType::Crl, None).unwrap();
    assert_eq!(serial, 2);
}

#[test]
fn test_increment_serial_with_explicit_number() {
    let mut db = test_db();
    // Explicit number greater than current → jumps forward
    let serial = db.increment_serial(SerialType::Cert, Some(200)).unwrap();
    assert_eq!(serial, 200);

    // Next call gets 201
    let serial = db.increment_serial(SerialType::Cert, None).unwrap();
    assert_eq!(serial, 201);
}

#[test]
fn test_increment_serial_explicit_lower_ignored() {
    let mut db = test_db();
    // Explicit number lower than current → ignored
    let serial = db.increment_serial(SerialType::Cert, Some(50)).unwrap();
    assert_eq!(serial, 100);
}

// -----------------------------------------------------------------------
// Certificates
// -----------------------------------------------------------------------

#[test]
fn test_add_and_query_cert() {
    let mut db = test_db();
    let cert = make_cert("100", "server.example.com", "20301231235959Z");
    db.add_cert(&cert).unwrap();

    let found = db
        .query_cert(&CertLookup::Serial("100".to_string()), false)
        .unwrap();
    assert!(found.is_some());
    let found = found.unwrap();
    assert_eq!(found.cn.as_deref(), Some("server.example.com"));
    assert_eq!(found.status.as_deref(), Some("Valid"));
}

#[test]
fn test_query_cert_by_cn() {
    let mut db = test_db();
    db.add_cert(&make_cert("100", "server.example.com", "20301231235959Z"))
        .unwrap();

    let found = db
        .query_cert(
            &CertLookup::Cn("server.example.com".to_string()),
            false,
        )
        .unwrap();
    assert!(found.is_some());
}

#[test]
fn test_query_cert_by_title() {
    let mut db = test_db();
    db.add_cert(&make_cert("100", "server.example.com", "20301231235959Z"))
        .unwrap();

    let found = db
        .query_cert(
            &CertLookup::Title("server.example.com".to_string()),
            false,
        )
        .unwrap();
    assert!(found.is_some());
}

#[test]
fn test_query_cert_valid_only() {
    let mut db = test_db();
    let mut cert = make_cert("100", "server.example.com", "20301231235959Z");
    cert.status = Some("Revoked".to_string());
    db.add_cert(&cert).unwrap();

    let found = db
        .query_cert(&CertLookup::Serial("100".to_string()), true)
        .unwrap();
    assert!(found.is_none());
}

#[test]
fn test_query_cert_not_found() {
    let db = test_db();
    let found = db
        .query_cert(&CertLookup::Serial("999".to_string()), false)
        .unwrap();
    assert!(found.is_none());
}

#[test]
fn test_update_cert() {
    let mut db = test_db();
    db.add_cert(&make_cert("100", "server.example.com", "20301231235959Z"))
        .unwrap();

    let mut updated = make_cert("100", "server.example.com", "20301231235959Z");
    updated.status = Some("Revoked".to_string());
    updated.revocation_date = Some("20260101000000Z".to_string());
    db.update_cert(&updated).unwrap();

    let found = db
        .query_cert(&CertLookup::Serial("100".to_string()), false)
        .unwrap()
        .unwrap();
    assert_eq!(found.status.as_deref(), Some("Revoked"));
    assert_eq!(found.revocation_date.as_deref(), Some("20260101000000Z"));
}

#[test]
fn test_update_nonexistent_cert_errors() {
    let mut db = test_db();
    let cert = make_cert("999", "nope.example.com", "20301231235959Z");
    let result = db.update_cert(&cert);
    assert!(result.is_err());
}

#[test]
fn test_count_certs() {
    let mut db = test_db();
    assert_eq!(db.count_certs().unwrap(), 0);

    db.add_cert(&make_cert("100", "a.example.com", "20301231235959Z"))
        .unwrap();
    db.add_cert(&make_cert("101", "b.example.com", "20301231235959Z"))
        .unwrap();
    assert_eq!(db.count_certs().unwrap(), 2);
}

// -----------------------------------------------------------------------
// External certificates
// -----------------------------------------------------------------------

fn make_ext_cert(serial: &str, cn: &str, expiry: &str) -> ExternalCertRecord {
    ExternalCertRecord {
        serial: serial.to_string(),
        cn: Some(cn.to_string()),
        title: Some(format!("EXT_{cn}")),
        status: Some("Valid".to_string()),
        expiry_date: Some(expiry.to_string()),
        subject: Some(format!("/CN={cn}")),
        issuer: Some("External CA".to_string()),
        issuer_subject: Some("/CN=External CA".to_string()),
        import_date: Some("20250101000000Z".to_string()),
        cert_type: Some("external".to_string()),
        not_before: Some("20250101000000Z".to_string()),
        key_type: Some("RSA".to_string()),
        key_size: Some(4096),
        san: None,
    }
}

#[test]
fn test_add_and_query_external_cert() {
    let mut db = test_db();
    db.add_external_cert(&make_ext_cert("200", "ext.example.com", "20301231235959Z"))
        .unwrap();

    let found = db
        .query_external_cert(&CertLookup::Serial("200".to_string()), false)
        .unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().cn.as_deref(), Some("ext.example.com"));
}

#[test]
fn test_query_all_external_certs() {
    let mut db = test_db();
    db.add_external_cert(&make_ext_cert("200", "a.ext.com", "20301231235959Z"))
        .unwrap();
    db.add_external_cert(&make_ext_cert("201", "b.ext.com", "20301231235959Z"))
        .unwrap();

    let all = db.query_all_external_certs(None).unwrap();
    assert_eq!(all.len(), 2);

    let valid = db.query_all_external_certs(Some("Valid")).unwrap();
    assert_eq!(valid.len(), 2);

    let expired = db.query_all_external_certs(Some("Expired")).unwrap();
    assert_eq!(expired.len(), 0);
}

#[test]
fn test_update_external_cert() {
    let mut db = test_db();
    db.add_external_cert(&make_ext_cert("200", "ext.example.com", "20301231235959Z"))
        .unwrap();

    let mut updated = make_ext_cert("200", "ext.example.com", "20301231235959Z");
    updated.status = Some("Expired".to_string());
    db.update_external_cert(&updated).unwrap();

    let found = db
        .query_external_cert(&CertLookup::Serial("200".to_string()), false)
        .unwrap()
        .unwrap();
    assert_eq!(found.status.as_deref(), Some("Expired"));
}

#[test]
fn test_count_external_certs() {
    let mut db = test_db();
    assert_eq!(db.count_external_certs().unwrap(), 0);
    db.add_external_cert(&make_ext_cert("200", "ext.com", "20301231235959Z"))
        .unwrap();
    assert_eq!(db.count_external_certs().unwrap(), 1);
}

// -----------------------------------------------------------------------
// CSRs
// -----------------------------------------------------------------------

#[test]
fn test_add_and_query_csr() {
    let db = test_db();
    let csr = CsrRecord {
        id: None,
        cn: Some("server.example.com".to_string()),
        title: Some("server.example.com".to_string()),
        csr_type: Some("server".to_string()),
        email: Some("admin@example.com".to_string()),
        subject: Some("/CN=server.example.com".to_string()),
        status: Some("Pending".to_string()),
        created_date: Some("20250101000000Z".to_string()),
        csr_pem: Some("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----".to_string()),
    };
    db.add_csr(&csr).unwrap();

    let found = db
        .query_csr(&CsrLookup::Cn("server.example.com".to_string()))
        .unwrap();
    assert!(found.is_some());
    let found = found.unwrap();
    assert_eq!(found.status.as_deref(), Some("Pending"));
    assert!(found.id.is_some());
}

#[test]
fn test_query_csr_by_id() {
    let db = test_db();
    let csr = CsrRecord {
        id: None,
        cn: Some("test.example.com".to_string()),
        title: Some("test.example.com".to_string()),
        csr_type: Some("server".to_string()),
        email: None,
        subject: None,
        status: Some("Pending".to_string()),
        created_date: None,
        csr_pem: None,
    };
    db.add_csr(&csr).unwrap();

    let found = db.query_csr(&CsrLookup::Id(1)).unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().cn.as_deref(), Some("test.example.com"));
}

#[test]
fn test_update_csr() {
    let db = test_db();
    let csr = CsrRecord {
        id: None,
        cn: Some("test.example.com".to_string()),
        title: Some("test.example.com".to_string()),
        csr_type: Some("server".to_string()),
        email: None,
        subject: None,
        status: Some("Pending".to_string()),
        created_date: None,
        csr_pem: None,
    };
    db.add_csr(&csr).unwrap();

    let updated = db
        .update_csr(&CsrRecord {
            id: Some(1),
            cn: None,
            title: None,
            csr_type: None,
            email: None,
            subject: None,
            status: Some("Signed".to_string()),
            created_date: None,
            csr_pem: None,
        })
        .unwrap();
    assert!(updated);

    let found = db.query_csr(&CsrLookup::Id(1)).unwrap().unwrap();
    assert_eq!(found.status.as_deref(), Some("Signed"));
}

#[test]
fn test_query_all_csrs() {
    let db = test_db();
    for cn in &["a.example.com", "b.example.com"] {
        db.add_csr(&CsrRecord {
            id: None,
            cn: Some(cn.to_string()),
            title: Some(cn.to_string()),
            csr_type: Some("server".to_string()),
            email: None,
            subject: None,
            status: Some("Pending".to_string()),
            created_date: None,
            csr_pem: None,
        })
        .unwrap();
    }

    let all = db.query_all_csrs(None).unwrap();
    assert_eq!(all.len(), 2);

    let pending = db.query_all_csrs(Some("Pending")).unwrap();
    assert_eq!(pending.len(), 2);

    let signed = db.query_all_csrs(Some("Signed")).unwrap();
    assert_eq!(signed.len(), 0);
}

// -----------------------------------------------------------------------
// CRL metadata
// -----------------------------------------------------------------------

#[test]
fn test_upsert_and_get_crl_metadata() {
    let db = test_db();
    assert!(db.get_crl_metadata().unwrap().is_none());

    db.upsert_crl_metadata(&CrlMetadata {
        issuer: Some("Test CA".to_string()),
        last_update: Some("20250101000000Z".to_string()),
        next_update: Some("20250201000000Z".to_string()),
        crl_number: Some(1),
        revoked_count: Some(0),
        revoked_json: Some("[]".to_string()),
    })
    .unwrap();

    let meta = db.get_crl_metadata().unwrap().unwrap();
    assert_eq!(meta.issuer.as_deref(), Some("Test CA"));
    assert_eq!(meta.crl_number, Some(1));

    // Upsert again (replace)
    db.upsert_crl_metadata(&CrlMetadata {
        issuer: Some("Test CA".to_string()),
        last_update: Some("20250201000000Z".to_string()),
        next_update: Some("20250301000000Z".to_string()),
        crl_number: Some(2),
        revoked_count: Some(3),
        revoked_json: Some("[\"100\",\"101\",\"102\"]".to_string()),
    })
    .unwrap();

    let meta = db.get_crl_metadata().unwrap().unwrap();
    assert_eq!(meta.crl_number, Some(2));
    assert_eq!(meta.revoked_count, Some(3));
}

// -----------------------------------------------------------------------
// OpenVPN templates
// -----------------------------------------------------------------------

#[test]
fn test_openvpn_template_crud() {
    let db = test_db();

    // Insert
    db.upsert_openvpn_template("default", "client\ndev tun\nproto udp", Some("20250101000000Z"))
        .unwrap();

    let tmpl = db.get_openvpn_template("default").unwrap().unwrap();
    assert_eq!(tmpl.name, "default");
    assert!(tmpl.content.contains("client"));

    // Update (upsert)
    db.upsert_openvpn_template("default", "client\ndev tap\nproto tcp", Some("20250201000000Z"))
        .unwrap();
    let tmpl = db.get_openvpn_template("default").unwrap().unwrap();
    assert!(tmpl.content.contains("tap"));

    // List
    db.upsert_openvpn_template("backup", "another template", None)
        .unwrap();
    let all = db.query_all_openvpn_templates().unwrap();
    assert_eq!(all.len(), 2);

    // Delete
    assert!(db.delete_openvpn_template("default").unwrap());
    assert!(!db.delete_openvpn_template("nonexistent").unwrap());
    assert_eq!(db.query_all_openvpn_templates().unwrap().len(), 1);
}

// -----------------------------------------------------------------------
// OpenVPN profiles
// -----------------------------------------------------------------------

#[test]
fn test_openvpn_profile_crud() {
    let db = test_db();

    db.add_openvpn_profile(&OpenVpnProfile {
        id: None,
        cn: "server.example.com".to_string(),
        title: "server.example.com_default".to_string(),
        created_date: Some("20250101000000Z".to_string()),
        template: Some("default".to_string()),
    })
    .unwrap();

    let profiles = db.query_all_openvpn_profiles().unwrap();
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].cn, "server.example.com");

    assert!(db
        .delete_openvpn_profile("server.example.com_default")
        .unwrap());
    assert!(db.query_all_openvpn_profiles().unwrap().is_empty());
}

// -----------------------------------------------------------------------
// process_ca_database
// -----------------------------------------------------------------------

#[test]
fn test_process_categorises_valid_certs() {
    let mut db = test_db();
    // Cert with far-future expiry → valid
    db.add_cert(&make_cert("100", "server.example.com", "20501231235959Z"))
        .unwrap();

    let changed = db.process_ca_database(None, false).unwrap();
    assert!(!changed);
    assert_eq!(db.certs_valid.len(), 1);
    assert!(db.certs_valid.contains("100"));
}

#[test]
fn test_process_categorises_expired_certs() {
    let mut db = test_db();
    // Cert with past expiry → expired
    db.add_cert(&make_cert("100", "expired.example.com", "20200101000000Z"))
        .unwrap();

    let changed = db.process_ca_database(None, false).unwrap();
    assert!(changed);
    assert_eq!(db.certs_expired.len(), 1);
    assert!(db.certs_expired.contains("100"));

    // Verify status was updated in DB
    let cert = db
        .query_cert(&CertLookup::Serial("100".to_string()), false)
        .unwrap()
        .unwrap();
    assert_eq!(cert.status.as_deref(), Some("Expired"));
}

#[test]
fn test_process_revokes_certificate() {
    let mut db = test_db();
    db.add_cert(&make_cert("100", "server.example.com", "20501231235959Z"))
        .unwrap();

    let changed = db.process_ca_database(Some("100"), false).unwrap();
    assert!(changed);
    assert_eq!(db.certs_revoked.len(), 1);
    assert!(db.certs_revoked.contains("100"));

    let cert = db
        .query_cert(&CertLookup::Serial("100".to_string()), false)
        .unwrap()
        .unwrap();
    assert_eq!(cert.status.as_deref(), Some("Revoked"));
    assert!(cert.revocation_date.is_some());
}

#[test]
fn test_process_not_dirty_no_revoke_returns_false() {
    let mut db = test_db();
    db.add_cert(&make_cert("100", "server.example.com", "20501231235959Z"))
        .unwrap();
    db.process_ca_database(None, false).unwrap();

    // Second call with no changes → false
    let changed = db.process_ca_database(None, false).unwrap();
    assert!(!changed);
}

#[test]
fn test_process_external_certs() {
    let mut db = test_db();
    db.add_external_cert(&make_ext_cert("200", "ext.valid.com", "20501231235959Z"))
        .unwrap();
    db.add_external_cert(&make_ext_cert("201", "ext.expired.com", "20200101000000Z"))
        .unwrap();

    db.process_ca_database(None, false).unwrap();

    assert_eq!(db.ext_certs_valid.len(), 1);
    assert!(db.ext_certs_valid.contains("200"));
    assert_eq!(db.ext_certs_expired.len(), 1);
    assert!(db.ext_certs_expired.contains("201"));
}

// -----------------------------------------------------------------------
// Export / Import roundtrip
// -----------------------------------------------------------------------

#[test]
fn test_export_import_roundtrip() {
    let mut db = test_db();
    db.add_cert(&make_cert("100", "server.example.com", "20301231235959Z"))
        .unwrap();
    db.add_cert(&make_cert("101", "client.example.com", "20301231235959Z"))
        .unwrap();
    db.add_external_cert(&make_ext_cert("200", "ext.example.com", "20301231235959Z"))
        .unwrap();

    let sql_bytes = db.export_database().unwrap();
    let sql_text = String::from_utf8(sql_bytes).unwrap();

    // Re-import into a fresh database
    let (db2, info) = CertificateAuthorityDB::from_sql_dump(&sql_text).unwrap();
    assert!(!info.migrated);

    assert_eq!(db2.count_certs().unwrap(), 2);
    assert_eq!(db2.count_external_certs().unwrap(), 1);

    let config = db2.get_config().unwrap();
    assert_eq!(config.next_serial, Some(100));
    assert_eq!(config.org.as_deref(), Some("Test Org"));
    assert_eq!(config.schema_version, Some(7));
}

#[test]
fn test_export_binary_starts_with_sqlite_header() {
    let db = test_db();
    let binary = db.export_database_binary().unwrap();
    // SQLite files start with "SQLite format 3\0"
    assert!(binary.starts_with(b"SQLite format 3\0"));
}

// -----------------------------------------------------------------------
// Schema migrations
// -----------------------------------------------------------------------

#[test]
fn test_v5_to_v7_migration() {
    // Create a v5-era SQL dump (no external_certificate table, no v7 columns)
    let v5_sql = r#"
BEGIN TRANSACTION;
CREATE TABLE config (
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
);
INSERT INTO "config" VALUES(1,'10','1','Test Org','Test OU','test@example.com','Sydney','NSW','AU','','',365,30,5,'','','');
CREATE TABLE certificate_authority (
    serial TEXT PRIMARY KEY,
    cn TEXT,
    title TEXT,
    status TEXT,
    expiry_date TEXT,
    revocation_date TEXT,
    subject TEXT,
    issuer TEXT
);
INSERT INTO "certificate_authority" VALUES('1','local.example.com','local.example.com','Valid','20301231235959Z',NULL,'/CN=local.example.com',NULL);
INSERT INTO "certificate_authority" VALUES('2','ext.example.com','ext.example.com','Valid','20301231235959Z',NULL,'/CN=ext.example.com','External CA');
CREATE TABLE csr (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cn TEXT,
    title TEXT,
    csr_type TEXT,
    email TEXT,
    subject TEXT,
    status TEXT,
    created_date TEXT
);
COMMIT;
"#;

    let (db, info) = CertificateAuthorityDB::from_sql_dump(v5_sql).unwrap();
    assert!(info.migrated);
    assert_eq!(info.from_version, 5);
    assert_eq!(info.to_version, 7);
    assert_eq!(info.steps.len(), 2); // v5→v6, v6→v7

    let config = db.get_config().unwrap();
    assert_eq!(config.schema_version, Some(7));

    // Local cert should remain in certificate_authority
    assert_eq!(db.count_certs().unwrap(), 1);
    let local = db
        .query_cert(&CertLookup::Cn("local.example.com".to_string()), false)
        .unwrap();
    assert!(local.is_some());

    // External cert (had issuer set) should have been migrated
    assert_eq!(db.count_external_certs().unwrap(), 1);
    let ext = db
        .query_external_cert(&CertLookup::Cn("ext.example.com".to_string()), false)
        .unwrap();
    assert!(ext.is_some());
    let ext = ext.unwrap();
    assert_eq!(ext.title.as_deref(), Some("EXT_ext.example.com"));
    assert_eq!(ext.issuer.as_deref(), Some("External CA"));

    // New tables should exist and be queryable
    assert!(db.get_crl_metadata().unwrap().is_none());
    assert!(db.query_all_openvpn_templates().unwrap().is_empty());
}

#[test]
fn test_current_schema_no_migration() {
    let db = test_db();
    let sql_bytes = db.export_database().unwrap();
    let sql_text = String::from_utf8(sql_bytes).unwrap();

    let (_, info) = CertificateAuthorityDB::from_sql_dump(&sql_text).unwrap();
    assert!(!info.migrated);
    assert!(info.steps.is_empty());
}

// -----------------------------------------------------------------------
// Dirty tracking
// -----------------------------------------------------------------------

#[test]
fn test_dirty_tracking() {
    let mut db = test_db();
    assert!(db.is_dirty());

    db.process_ca_database(None, false).unwrap();
    assert!(!db.is_dirty());

    db.add_cert(&make_cert("100", "server.example.com", "20501231235959Z"))
        .unwrap();
    assert!(db.is_dirty());
}

// -----------------------------------------------------------------------
// Iterdump format
// -----------------------------------------------------------------------

#[test]
fn test_iterdump_contains_expected_structure() {
    let mut db = test_db();
    db.add_cert(&make_cert("100", "server.example.com", "20301231235959Z"))
        .unwrap();

    let sql = String::from_utf8(db.export_database().unwrap()).unwrap();

    assert!(sql.starts_with("BEGIN TRANSACTION;\n"));
    assert!(sql.ends_with("COMMIT;\n"));
    assert!(sql.contains("CREATE TABLE"));
    assert!(sql.contains("INSERT INTO"));
    assert!(sql.contains("\"certificate_authority\""));
    assert!(sql.contains("'server.example.com'"));
}

#[test]
fn test_iterdump_null_handling() {
    let mut db = test_db();
    let cert = CertRecord {
        serial: "100".to_string(),
        cn: Some("test.example.com".to_string()),
        title: None,
        status: Some("Valid".to_string()),
        expiry_date: None,
        revocation_date: None,
        subject: None,
        cert_type: None,
        not_before: None,
        key_type: None,
        key_size: None,
        issuer: None,
        san: None,
    };
    db.add_cert(&cert).unwrap();

    let sql = String::from_utf8(db.export_database().unwrap()).unwrap();
    assert!(sql.contains("NULL"));
}

#[test]
fn test_iterdump_single_quote_escaping() {
    let mut db = test_db();
    let cert = CertRecord {
        serial: "100".to_string(),
        cn: Some("it's a test".to_string()),
        title: Some("it's a test".to_string()),
        status: Some("Valid".to_string()),
        expiry_date: Some("20301231235959Z".to_string()),
        revocation_date: None,
        subject: Some("/CN=it's a test".to_string()),
        cert_type: None,
        not_before: None,
        key_type: None,
        key_size: None,
        issuer: None,
        san: None,
    };
    db.add_cert(&cert).unwrap();

    let sql = String::from_utf8(db.export_database().unwrap()).unwrap();
    assert!(sql.contains("'it''s a test'"));
}
