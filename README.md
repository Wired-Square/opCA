# OPCA — 1Password Certificate Authority

OPCA is a desktop PKI toolkit that manages keys, CSRs, certificates, CRLs, and more — all stored
securely in [1Password](https://1password.com) via the 1Password CLI. No sensitive data is ever
written to disk.

Built with [Tauri 2](https://v2.tauri.app), a Rust backend ([opca-core](rust/crates/opca-core)),
and a [SolidJS](https://www.solidjs.com) frontend.

- **Cross-platform** desktop app (macOS, Linux, Windows)
- **No sensitive data written to disk** — all secrets stay in 1Password
- **Full certificate lifecycle** — create, renew, revoke, import, export

> **Upgrading from the Python CLI?** See [Python CLI (Deprecated)](#python-cli-deprecated) below.

---

## Features

### Certificate Management
- Create certificates of type: **webserver**, **vpnserver**, **vpnclient**, **device**
- Renew certificates (retains private key and original settings)
- Revoke certificates by common name or serial number
- Import externally-signed certificates with optional chain
- Export in PEM or PKCS#12 format
- Bulk creation from profile files

### Certificate Signing Requests
- Generate CSRs and private keys
- Sign external CSRs with your CA
- Import externally-signed certificates back into CSR entries

### CRL & Publishing
- Generate Certificate Revocation Lists
- Export in PEM or DER format
- Upload CA certificate and CRL to S3 or other endpoints

### OpenVPN
- Generate Diffie-Hellman parameters and TLS auth keys
- Manage OpenVPN server configuration objects
- Create and customise config templates
- Generate client `.ovpn` profiles (single or bulk)

### DKIM
- Generate DKIM key pairs
- Deploy DKIM DNS records to AWS Route53
- Verify DNS publication

### Database & Vault
- Track all issued, revoked, and expired certificates
- View and modify CA configuration
- Encrypted vault backup and restore
- Vault locking for concurrent-access safety

---

## Requirements

- [1Password CLI (`op`)](https://developer.1password.com/docs/cli/get-started) — signed in to at least one account
- [Rust toolchain](https://rustup.rs) and [Node.js](https://nodejs.org) (for building from source)

---

## Installation

Download the latest release for your platform from
[GitHub Releases](https://github.com/wiredsquare/opCA/releases).

| Platform | Artifact |
|---|---|
| macOS (Apple Silicon) | `.dmg` (aarch64) |
| macOS (Intel) | `.dmg` (x86_64) |
| Linux | `.AppImage` / `.deb` |
| Windows | `.msi` / `.exe` |

### Build from Source

```shell
cd rust
npm install
npm run tauri build
```

The built application will be in `rust/crates/opca-tauri/target/release/bundle/`.

### Development

```shell
cd rust
npm install
npm run tauri dev
```

This starts the SolidJS dev server on `localhost:5173` with hot-reload and launches the Tauri window.

---

## Quick Start

Create a dedicated vault in 1Password for your private CA:

```shell
op signin --account <acct>
op vault create CA-Test --icon wrench
```

Launch OPCA, connect to your 1Password account, select the vault, and use the GUI to:

1. **Initialise a CA** — set organisation details, validity periods, and distribution URLs
2. **Create certificates** — webserver, VPN server/client, device, or sign external CSRs
3. **Manage the lifecycle** — renew, revoke, and track certificates via the built-in database
4. **Generate CRLs** — create and optionally upload Certificate Revocation Lists
5. **OpenVPN integration** — generate DH parameters, TA keys, config templates, and client profiles
6. **DKIM management** — create DKIM keys and deploy DNS records via Route53
7. **Vault backup/restore** — AES-256-GCM encrypted backups with password protection

---

## Architecture

OPCA is an `opca-core` Rust library wrapped by a Tauri 2 shell and a SolidJS
frontend. A standalone AWS Lambda
([notification/](notification/)) handles scheduled expiry monitoring.

See [docs/architecture.md](docs/architecture.md) for the full walkthrough of
crates, vault layout, locking model, and the lifecycle of a typical
operation.

---

## Testing

### Unit Tests

Run the Rust unit tests (no external dependencies):

```shell
cargo test -p opca-core
```

### Integration Tests

Integration tests require the 1Password CLI installed and an active session:

```shell
OPCA_INTEGRATION_TEST=1 cargo test -p opca-core --test op_integration
```

Set `OPCA_TEST_VAULT` and optionally `OPCA_TEST_ACCOUNT` to configure the test vault.

---

## Python CLI (Deprecated)

The original Python CLI/TUI implementation (`python/`) is **deprecated** and in a read-only
archive state. It will not receive new features or bug fixes.

The Python version is still available on [PyPI](https://pypi.org/project/opca/) for existing
users who need it:

```shell
pip install opca
```

The final Python release is **v0.99.7**. All new development is in the Tauri/Rust desktop
application. Both implementations share the same 1Password vault format, so existing vaults
work with the new version without migration.

For the Python CLI documentation, refer to the [v0.99.7 release](https://github.com/wiredsquare/opCA/releases/tag/v0.99.7).

---

## Licence

MIT &copy; Wired Square

[1password]: https://www.1password.com
[1password-cli]: https://developer.1password.com/docs/cli/get-started
[openvpn]: https://openvpn.net
