# OPCA Architecture

OPCA is a desktop Certificate Authority whose "disk" is a 1Password vault.
Every private key, certificate, database snapshot, CRL, and OpenVPN artefact
lives as a 1Password item — nothing sensitive is written to the local
filesystem.

This document describes how the Rust + Tauri desktop app fits together.

---

## Component overview

```
┌───────────────────────────────┐
│  Frontend — SolidJS + Vite    │   (rust/frontend)
│  Pages · API wrappers · Store │
└──────────────┬────────────────┘
               │  Tauri invoke() — JSON IPC
┌──────────────▼────────────────┐
│  Tauri shell — opca-tauri     │   (rust/crates/opca-tauri)
│  Command handlers · AppState  │
└──────────────┬────────────────┘
               │  Rust function calls
┌──────────────▼────────────────┐
│  Core library — opca-core     │   (rust/crates/opca-core)
│  CA · crypto · services · Op  │
└──────────────┬────────────────┘
               │  std::process::Command
┌──────────────▼────────────────┐
│  1Password CLI (`op`)         │   ← authentication, vault I/O
└──────────────┬────────────────┘
               │  HTTPS
         ┌─────▼──────┐
         │ 1Password  │   ← durable storage for all CA state
         └────────────┘
```

Two workspace crates plus a frontend make up the desktop app:

| Component | Role |
|---|---|
| [opca-core](../rust/crates/opca-core) | Framework-free Rust library. Contains all PKI logic, the 1Password wrapper, services, and error types. |
| [opca-tauri](../rust/crates/opca-tauri) | Tauri 2 desktop shell. Thin IPC layer that exposes `opca-core` to the webview. |
| [frontend](../rust/frontend) | SolidJS + Vite single-page app rendered in the Tauri webview. |

---

## Core library (`opca-core`)

Organised by concern under [src/](../rust/crates/opca-core/src):

- [op.rs](../rust/crates/opca-core/src/op.rs) — thin wrapper around the
  1Password CLI. The `CommandRunner` trait abstracts process invocation;
  `ShellRunner` shells out to `op`, and unit tests inject a `MockRunner` to
  avoid real CLI calls. Private-key arguments are redacted from debug logs.
- [vault_lock.rs](../rust/crates/opca-core/src/vault_lock.rs) — advisory lock
  implemented as a 1Password Secure Note (`CA_Lock`). `op item create` acts as
  an atomic compare-and-swap; stale locks past TTL are broken automatically.
- [crypto/](../rust/crates/opca-core/src/crypto) — key generation, CRL/DKIM/
  OpenVPN helpers, and PKCS#12 packaging via the `openssl` crate.
- [services/](../rust/crates/opca-core/src/services):
  - [ca.rs](../rust/crates/opca-core/src/services/ca.rs) — the
    `CertificateAuthority` struct. Orchestrates init, sign, revoke, renew,
    rekey, CRL generation, and upload. This is the capstone API the Tauri
    layer calls into.
  - [cert.rs](../rust/crates/opca-core/src/services/cert.rs) —
    per-certificate bundle operations (build, sign, import/export, inspect).
  - [database/](../rust/crates/opca-core/src/services/database) — in-memory
    SQLite (`rusqlite`) holding the CA config and every issued/external
    certificate, CSR, CRL metadata record, and OpenVPN template/profile. The
    whole DB is serialised and persisted as the `CA_Database` document in
    1Password. A schema-version field drives automatic migrations.
  - [command_queue.rs](../rust/crates/opca-core/src/services/command_queue.rs)
    — batches write operations (`store_item`, `store_document`, `rename`,
    `delete`) in memory. Duplicate writes to the same target are collapsed so
    only the final state is flushed to 1Password. Never persisted — payloads
    contain secret material.
  - [storage/](../rust/crates/opca-core/src/services/storage) — publishing
    backends behind a `StorageBackend` trait: `rsync://`, `sftp://`/`scp://`,
    and `s3://` (AWS credentials sourced via the `op` CLI plugin). A URI
    factory picks the right backend per upload.
  - [route53.rs](../rust/crates/opca-core/src/services/route53.rs) — AWS SDK
    calls for DKIM TXT record deployment and verification.
  - [backup.rs](../rust/crates/opca-core/src/services/backup.rs) — encrypted
    file format: 4-byte magic `OPCA` + version + 16-byte salt + 12-byte
    nonce + 16-byte GCM tag + AES-256-GCM ciphertext. Key derivation is
    PBKDF2-HMAC-SHA256, 600 000 iterations. Plaintext never touches disk.
  - [vault.rs](../rust/crates/opca-core/src/services/vault.rs) — enumerates
    every CA-related item in a vault and serialises them into the JSON
    payload consumed by `backup`.
- [error.rs](../rust/crates/opca-core/src/error.rs) — `OpcaError`, a single
  `thiserror` enum that every layer returns. Serialises as `{kind, message}`
  so the frontend can pattern-match error types.

---

## 1Password vault as the source of truth

OPCA stores nine logical kinds of item. Titles and field labels are fixed in
[constants.rs](../rust/crates/opca-core/src/constants.rs).

| Item | Title | Kind | Purpose |
|---|---|---|---|
| CA | `CA` | Secure Note | CA certificate, private key, subject, validity, serial counters |
| Database | `CA_Database` | Document | SQLite dump of every tracked cert/CSR/CRL/VPN record |
| CRL | `CRL` | Document | Latest published Certificate Revocation List |
| OpenVPN | `OpenVPN` | Secure Note | DH params, TLS-auth static key, server template |
| Certificate | `<cn>` | Secure Note | One item per issued cert (key + cert + chain + type) |
| External cert | `<cn>` | Secure Note | Imported certificates not signed by this CA |
| CSR | `<cn>` | Secure Note | Unsigned or awaiting-sign requests |
| DKIM | `<selector>._domainkey.<domain>` | Secure Note | DKIM key pair and metadata |
| Lock | `CA_Lock` | Secure Note | Advisory lock for concurrent-write safety |

### Why a shadow SQLite database?

Listing and filtering certificates purely through `op` is slow and has no join
or index support. OPCA keeps a full SQLite mirror in memory, consults it for
every query, and re-serialises it to the `CA_Database` document whenever the
catalogue changes. The dump is keyed by a `download_fingerprint` so stale
local state is detected on reconnect.

### Concurrent-writer safety

Any mutating operation goes through `VaultLock`:

1. Acquire — `op item create CA_Lock …` fails if a lock already exists. If it
   does, OPCA parses the holder metadata (email, hostname, acquired-at, TTL)
   and either waits, breaks a stale lock, or refuses the operation.
2. Perform the mutation through the command queue.
3. Flush the queue to 1Password.
4. Release — delete `CA_Lock`.

The frontend wraps write calls in `withLock()` in
[api/tauri.ts](../rust/frontend/src/api/tauri.ts) so the lock lifetime always
matches a single logical operation.

---

## Tauri shell (`opca-tauri`)

- [main.rs](../rust/crates/opca-tauri/src/main.rs) — Tauri builder. Registers
  the `log`, `dialog`, and `shell` plugins; extends `PATH` on macOS so bundled
  `.app` builds can find Homebrew-installed `op`; pre-warms `op --version` so
  macOS AMFI/OCSP verification is cached before the first real call.
- [state.rs](../rust/crates/opca-tauri/src/state.rs) — `AppState`, Tauri's
  managed singleton. Three mutex-guarded fields:
  - `conn: Connection { op, ca }` — the live 1Password handle and the loaded
    `CertificateAuthority`. A single mutex makes connect/disconnect atomic
    with respect to in-flight operations. `ensure_ca()` lazily retrieves the
    CA from 1Password on first use.
  - `vault_lock: VaultLock` — the current process's advisory lock handle.
  - `action_log: Vec<LogEntry>` — in-memory audit trail surfaced on the Log
    page.
- [commands/](../rust/crates/opca-tauri/src/commands) — one module per
  feature area (`ca`, `cert`, `crl`, `csr`, `database`, `dkim`, `openvpn`,
  `vault`, `lock`, `connect`, `dashboard`, `files`, `logs`, `update`). Each
  module exposes `#[tauri::command]` async functions that deserialise DTOs,
  call into `opca-core`, and return serialisable results. DTO shapes are
  defined in [commands/dto.rs](../rust/crates/opca-tauri/src/commands/dto.rs).

The shell is intentionally thin: no PKI logic lives here, only glue between
the webview and `opca-core`.

### Dashboard as a persisting command

`get_dashboard` is the one read-shaped command that can also write. It forces
a fresh rescan of the certificate database (passing `force=true` to
`process_ca_database`) so that passage-of-time state transitions —
specifically, a certificate crossing its `not_after` and flipping to
`Expired` — are detected on every refresh. When the rescan mutates any rows,
the command calls `store_ca_database()` so the transition lands in 1Password
immediately, without waiting for an unrelated write op (revoke, sign, CRL
generate) to flush the change.

The DTO surfaces both a reshaped CA status (value + expiry + graduated
warning) and a mirrored CRL status (next_update + graduated warning from
`assess_crl_expiry`), along with a `pending_csrs` count and an
`action_items: Vec<ActionItemDto>` list. Action items carry a stable `id`,
severity, human-readable message, button label, and an `action` token that
the frontend dispatches on (`regenerate_and_upload_crl`, `regenerate_crl`,
`view_expired_certs`, `view_pending_csrs`, `view_ca`). Threshold logic lives
entirely in the Rust layer to avoid duplication in TypeScript.

---

## Frontend (`rust/frontend`)

A single-page SolidJS app. Key conventions:

- [App.tsx](../rust/frontend/src/App.tsx) routes based on `vaultState`
  (`valid_ca` / `empty_vault` / `invalid_ca`) returned by `connect`. Empty
  vaults are steered to CA initialisation; broken vaults to the dashboard
  with an error banner.
- [api/](../rust/frontend/src/api) — one file per feature, each a typed
  wrapper around `tauriInvoke` from
  [api/tauri.ts](../rust/frontend/src/api/tauri.ts). `tauriInvoke`
  centralises error surfacing and the in-flight-operation indicator;
  `withLock()` wraps any mutation in acquire/release calls.
- [stores/](../rust/frontend/src/stores) — small reactive stores (`app`,
  `operation`, `theme`, `update`). No global state framework.
- [pages/](../rust/frontend/src/pages) mirror the Tauri command modules
  roughly 1-to-1.

---

## Lifecycle of a typical operation

1. User clicks **Revoke** on a certificate in the webview.
2. The SolidJS page calls `revokeCertificate()` in `api/certs.ts`.
3. `withLock("cert_revoke", …)` acquires `CA_Lock` via `acquire_lock`.
4. The page invokes `revoke_certificate` — a `#[tauri::command]` handler.
5. The handler calls `AppState::ensure_ca()` to get (or lazily load) the CA.
6. `CertificateAuthority::revoke_certificate` mutates the SQLite DB,
   regenerates the CRL, and enqueues the writes (`store_item`,
   `store_document`).
7. The queue flushes — each queued op becomes an `op` CLI invocation.
8. The handler serialises the result; the frontend updates its view.
9. `withLock` releases `CA_Lock` in its `finally` clause.
10. An entry lands in `action_log` for display on the Log page.

If any step fails, the error propagates as an `OpcaError` through every
layer and is surfaced in the UI via `setAppState("error", …)`.

---

## Testing

- **Unit** — `cargo test -p opca-core`. Uses `MockRunner` to feed canned `op`
  output; no network, no `op` binary required.
- **Integration** — `OPCA_INTEGRATION_TEST=1 cargo test -p opca-core --test
  op_integration`. Requires an `op` session and a real test vault
  (`OPCA_TEST_VAULT`, optionally `OPCA_TEST_ACCOUNT`).

---

## Lambda notification

The desktop app is not a server — it only runs when a user opens it.
Long-term expiry monitoring is handled by a standalone AWS Lambda in
[notification/aws_lambda.py](../notification/aws_lambda.py). It runs on a
schedule (EventBridge) and posts a Slack summary of CA health.

### How it plugs into OPCA

The Lambda reads the artefacts OPCA uploads through its storage backends:

- `CA_Database` (SQLite dump) is uploaded to a **private** S3 bucket via the
  CLI `Database › Upload` flow (`s3://…/db_key`).
- `CA` certificate and the `CRL` are uploaded to a **public** S3 bucket via
  the `CA › Upload` and `CRL › Upload` flows.

The Lambda never talks to 1Password and never touches private keys — it only
needs the already-published database dump, CA certificate, and CRL.

### What it checks

[`lambda_handler`](../notification/aws_lambda.py) orchestrates three S3
downloads and calls `run_tests`, which reports on:

- **CA database freshness** — age of the S3 object vs. the `DAYS` threshold.
- **Issued certificates** — SQL query against the `certificate_authority`
  table for any non-revoked cert expiring within `DAYS`.
- **External certificates** — same check against the `external_certificate`
  table (rows with `status = 'Valid'`).
- **CA certificate validity** — current validity plus an upcoming-expiry
  warning at `DAYS`.
- **CRL signature** — verified against the CA certificate's public key using
  `cryptography`.
- **CRL file age** — age of the S3 object vs. `DAYS`.
- **CRL `nextUpdate`** — already-expired is flagged as an error; within
  `CRL_DAYS` is flagged as a warning.

Results are concatenated into a single Slack-formatted message. Any failing
check sets a `warning` flag that switches the Slack bot icon from
`:robot_face:` to `:warning:`.

### Configuration

All inputs come from environment variables set on the Lambda — see
[notification/environment.sh.example](../notification/environment.sh.example)
for the canonical list. Key ones:

| Variable | Purpose |
|---|---|
| `DAYS` | Expiry/age threshold in days for certs and DB |
| `CRL_DAYS` | Threshold for CRL `nextUpdate` warnings |
| `PRIVATE_BUCKET`, `DB_KEY`, `LOCAL_DB_PATH` | Where the CA database dump lives in S3 and where to stage it |
| `PUBLIC_BUCKET`, `CA_CERT_KEY`, `CRL_KEY` | Where the published CA cert and CRL live |
| `SLACK_USER`, `SLACK_URL` | Slack bot identity and webhook |

The Lambda stays in Python because it is a tiny, infrequent cron job with no
1Password dependency — keeping it separate from the desktop app means the
user's 1Password session is not part of the monitoring loop.
