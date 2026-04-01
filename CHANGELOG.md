# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- DKIM: show expected and found DNS records when verification detects a mismatch
- DKIM: native DNS TXT lookups via hickory-resolver, replacing `dig` shell-out
- DKIM: key info now opens in a modal dialog instead of rendering inline
- DKIM: key table grows to fill available vertical space instead of fixed 240px height
- Certificate rekey operation: renew a certificate with a newly generated private key, preserving subject attributes and SANs
- Allow rekeying revoked and expired certificates to issue a new key and certificate with the same subject details
- Relative time display mode: the UTC/Local timezone toggle now cycles through a third "Relative" mode that shows expiry dates as live countdowns (e.g. "2y 3mo", "4h 12m 30s") and past dates as time ago (e.g. "3 months ago")
- Search input on list views: Certificates, CSR, DKIM, OpenVPN profiles, and Database activity log now support client-side text search across all visible columns
- Vault backup: optional "Generate" button creates a strong random password (URL-safe base64, 32 bytes)
- Vault backup: optional "Store password in 1Password" saves the encryption password as a Password item in the current vault
- Vault backup: optional "Transfer backup to store" uploads the encrypted backup to the configured backup store (rsync/S3)
- Vault backup: display MD5 hash of the backup file on success
- Vault backup: include MD5 hash in the 1Password password item when storing the encryption password
- Vault backup: vault picker to choose an alternate vault for 1Password password storage
- Vault restore: display MD5 hash of the selected backup file before restoring
- macOS: `NSLocalNetworkUsageDescription` in Info.plist for local network permission prompt on first launch

### Changed

- Certificate naming: items are now named `CRT_{serial}_{cn}` instead of just the CN, making each item uniquely identifiable
- Certificate renewal and revocation no longer rename the original 1Password item
- Renewal guard now checks certificate status (rejects revoked) instead of comparing title to serial
- OpenVPN: Profiles tab is now the default view and appears first in the tab bar
- Bump GitHub Actions (`checkout`, `setup-node`, `upload-artifact`) from v4 to v5 for Node.js 24 compatibility

### Fixed

- Certificate creation failed for non-Device types — the create form sent display labels (e.g. "Web Server") instead of parser-compatible values (e.g. "webserver")
- Rsync backup store connection test now handles daemon module syntax (`host::module`) correctly — previously the module name was included in the hostname, causing DNS resolution failure
- Suppress unused variable warning for `mode` parameter on Windows in `write_bytes`
- Move `std::io::Write` import into `#[cfg(unix)]` block in vault backup to fix unused import warning on Windows

## [0.99.10] - 2026-03-17

### Changed

- S3 credential fetching rewritten to read the 1Password AWS plugin config (`~/.config/op/plugins/aws.json`) and fetch credentials directly via `op item get`, replacing `op plugin run` which could hang in non-interactive/GUI contexts
- Pass 1Password account through to storage backend calls

### Fixed

- Subprocess stdin set to null when no input is provided, preventing potential hangs from inherited stdin

### Added

- `test` and `test:e2e` npm scripts in `rust/package.json`

## [0.99.9] - 2026-03-17

### Added

- CA certificate re-sign: extend CA validity with the same key pair via `ca resign` CLI command or the "Re-sign Certificate" button on the CA Certificate tab — re-signs with new `not_before`/`not_after` dates without regenerating keys or reissuing certificates
- Graduated CA expiry warnings: critical (<30 days), prominent (<6 months), and cert-lifetime-exceeds-CA tiers, displayed in CLI after `ensure_ca` and on the Tauri dashboard
- Warn-but-allow policy when issuing or renewing certificates that would outlive the CA
- 6-month caution tier for certificate expiry categorisation in the database (`certs_expires_warning` / `ext_certs_expires_warning`)
- File-based logging via `tauri-plugin-log` — timestamped debug logs written to `~/Library/Logs/opCA/opca.log` with 5 MB rotation, covering all `op` CLI calls, CA operations, and storage backends
- Structured `log` crate integration across `opca-core`: `op` command execution, CA operations, storage backends, and S3 uploads all emit debug/info/error log messages instead of raw `eprintln!`
- Rust CLI (`opca-cli` crate): complete command-line interface replacing the deprecated Python CLI, with all 8 command groups (ca, cert, crl, csr, database, dkim, openvpn, vault) and 35 subcommands using clap v4
- Update notification: checks GitHub releases on startup and displays a badge in the sidebar and login view when a newer version is available
- Sidebar operation status: shows the currently active op CLI operation (with spinner) at the bottom of the sidebar

### Fixed

- CA initialisation now correctly passes Common Name and CA certificate validity (`--ca-days`) through `CaConfig` to the certificate bundle, fixing `ca init` failures
- `store_ca_database` uses `StoreAction::Auto` instead of hardcoded `Edit`, fixing document creation during `ca init` and `database rebuild`
- `op` CLI stdin pipe now closed after writing, preventing 30-second timeouts on `document create` operations
- macOS production build performance: reduced `op` CLI process spawns per operation by eliminating redundant `item_exists` probes, fingerprint re-downloads, and `StoreAction::Auto` lookups
- Certificate backfill now returns detail to the UI immediately and persists the database to 1Password in the background
- Added AMFI/OCSP cache warmup at startup (`op --version`) so first real `op` call is not penalised by macOS code-signature verification
- Added 30-second timeout on `op` CLI calls to prevent indefinite hangs
- Added macOS hardened-runtime entitlements (`disable-library-validation`, `automation.apple-events`, `inherit`) for reliable child-process IPC in signed builds
- Store connection test now fetches AWS credentials once and reuses them across all S3 stores, and spawns `op plugin run` directly with a 5-minute timeout to handle slow AMFI verification in hardened-runtime builds

## [0.99.8] - 2026-03-15

### Added

- Complete rewrite from Python CLI/TUI to Rust desktop application using Tauri 2 and SolidJS
- Native desktop UI replacing the Textual TUI with a SolidJS frontend
- 1Password integration via `op` CLI with `CommandRunner` trait for testability
- Certificate management: create, renew, revoke, import with chain and encrypted key support
- CA initialisation and restoration from 1Password vault backup
- CSR signing, CRL generation, DKIM key management, and OpenVPN profile support
- Database service with SQLite and schema migrations
- Vault locking for safe concurrent access
- Storage backends: S3 and rsync for certificate distribution
- Route53 DNS integration for ACME challenges
- GitHub Actions CI/CD with builds for macOS (Apple Silicon + Intel), Linux, and Windows
- Apple code signing and notarisation support

## [0.99.7] - 2026-03-15

### Added

- Schema version gate: the Python implementation now refuses to load a database with a schema version newer than it supports (v7), preventing data corruption when the Rust rewrite evolves the schema
- Empty vault gating: sidebar items and keyboard shortcuts for screens that require a CA are disabled until a CA is initialised or restored
- Empty vault badge in the screen header when connected to a vault with no CA
- Vault Backup tab is disabled on an empty vault; the screen defaults to Restore
- Certificate import: passphrase field for encrypted private keys with automatic decryption and re-export as unencrypted PKCS8 PEM
- Certificate import: certificate chain field for intermediate CA certificates, stored as `certificate_chain` in 1Password
- `certificate_chain` field on CertificateBundle for holding intermediate CA PEM data
- `chain_item` key in DEFAULT_OP_CONF for the 1Password field label
- Database schema v7: certificate metadata columns (cert_type, not_before, key_type, key_size, issuer, SAN) on certificate_authority and external_certificate tables
- Database schema v7: csr_pem column on csr table
- Database schema v7: crl_metadata, openvpn_template, and openvpn_profile tables with CRUD helpers
- CommandQueue service for batching and debouncing 1Password write operations
- Certificate metadata extraction (key type, key size, SAN) in CA format_db_item()
- VaultLock: advisory locking via a 1Password Secure Note (CA_Lock) to serialise mutating operations across CLI and TUI
- Stale-database detection on store_ca_database() using download fingerprint comparison
- TuiContext.locked_mutation() context manager for TUI screens that acquires the vault lock and refreshes the CA database

### Changed

- Certificate import screen now calls CA services directly instead of shelling out via capture_handler(), improving error handling and chain support
- Certificate import stores chain data via store_certbundle() when provided
- Database migration steps v4→v5 and v5→v6 now use inline schemas to avoid forward-compatibility issues with later table definitions
- CLI commands (ca init/import, cert create/renew/revoke/import, crl create) now acquire the vault lock before mutating operations
- TUI screens (cert create/renew/revoke, CRL generate, CA config save/init) now use locked_mutation()

### Fixed

- TUI no longer shows raw Python log lines (e.g. vault_lock INFO messages) in the terminal; StreamHandlers are removed on startup and restored on exit
- Vault restore no longer prints raw Python log lines in the TUI (demoted to debug level; progress is shown via LogPanel callback)
- count_certs() no longer crashes when fetchone() returns None on a replaced database connection
- TUI e2e test helper connect_and_get_dashboard now waits for the Dashboard's _show_welcome worker to complete
