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
│  Frontend — SolidJS + Vite    │   (frontend)
│  Pages · API wrappers · Store │
└──────────────┬────────────────┘
               │  Tauri invoke() — JSON IPC
┌──────────────▼────────────────┐
│  Tauri shell — opca-tauri     │   (crates/opca-tauri)
│  Command handlers · AppState  │
└──────────────┬────────────────┘
               │  Rust function calls
┌──────────────▼────────────────┐
│  Core library — opca-core     │   (crates/opca-core)
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
| [opca-core](../crates/opca-core) | Framework-free Rust library. Contains all PKI logic, the 1Password wrapper, services, and error types. |
| [opca-tauri](../crates/opca-tauri) | Tauri 2 desktop shell. Thin IPC layer that exposes `opca-core` to the webview. |
| [frontend](../frontend) | SolidJS + Vite single-page app rendered in the Tauri webview. |

---

## Core library (`opca-core`)

Organised by concern under [src/](../crates/opca-core/src):

- [op.rs](../crates/opca-core/src/op.rs) — thin wrapper around the
  1Password CLI. The `CommandRunner` trait abstracts process invocation;
  `ShellRunner` shells out to `op`, and unit tests inject a `MockRunner` to
  avoid real CLI calls. Private-key arguments are redacted from debug logs.
- [vault_lock.rs](../crates/opca-core/src/vault_lock.rs) — advisory lock
  implemented as a 1Password Secure Note (`CA_Lock`). `op item create` acts as
  an atomic compare-and-swap; stale locks past TTL are broken automatically.
- [crypto/](../crates/opca-core/src/crypto) — key generation, CRL/DKIM/
  OpenVPN helpers, and PKCS#12 packaging via the `openssl` crate.
- [services/](../crates/opca-core/src/services):
  - [ca.rs](../crates/opca-core/src/services/ca.rs) — the
    `CertificateAuthority` struct. Orchestrates init, sign, revoke, renew,
    rekey, CRL generation, and upload. This is the capstone API the Tauri
    layer calls into.
  - [cert.rs](../crates/opca-core/src/services/cert.rs) —
    per-certificate bundle operations (build, sign, import/export, inspect).
    `KeyAlgorithm` (`ec-p256`, `ec-p384`, `rsa-2048`, `rsa-4096`) picks the key;
    `CertType::default_key_algorithm` gives EC P-256 for leaves, EC P-384 for the
    CA and RSA 2048 for Apple developer CSRs, and a rekey keeps the existing
    family unless given an algorithm (`rekey_cert`, `bulk_rekey_certs` and
    `opca cert rekey --key` take one). `signing_digest` uses SHA-384 for P-384 keys, SHA-256 otherwise, and
    `keyEncipherment` is only set on RSA leaves.
  - [san.rs](../crates/opca-core/src/services/san.rs) — Subject
    Alternative Names: `SubjectAltName` (DNS, IP, email, URI) parses and
    validates user input, and `of_certificate` / `of_csr` read them back from
    the extension. The frontend's `utils/san.ts` mirrors its parsing rules.
  - [database/](../crates/opca-core/src/services/database) — in-memory
    SQLite (`rusqlite`) holding the CA config and every issued/external
    certificate, CSR, CRL metadata record, CRL batch record, and OpenVPN
    template/profile. The whole DB is serialised and persisted as the
    `CA_Database` document in 1Password. A schema-version field drives
    automatic, forward-only migrations (currently v15).
  - [command_queue.rs](../crates/opca-core/src/services/command_queue.rs)
    — batches write operations (`store_item`, `store_document`, `rename`,
    `delete`) in memory. Duplicate writes to the same target are collapsed so
    only the final state is flushed to 1Password. Never persisted — payloads
    contain secret material.
  - [storage/](../crates/opca-core/src/services/storage) — publishing
    backends behind a `StorageBackend` trait: `rsync://`, `sftp://`/`scp://`,
    and `s3://`. A URI factory picks the right backend per upload. AWS
    credentials are read straight from a 1Password item with `op item get`
    (see [AWS credentials](#aws-credentials)).
  - [route53.rs](../crates/opca-core/src/services/route53.rs) — AWS SDK
    calls for DKIM TXT record deployment and verification.
  - [backup.rs](../crates/opca-core/src/services/backup.rs) — encrypted
    file format: 4-byte magic `OPCA` + version + 16-byte salt + 12-byte
    nonce + 16-byte GCM tag + AES-256-GCM ciphertext. Key derivation is
    PBKDF2-HMAC-SHA256, 600 000 iterations. Plaintext never touches disk.
  - [vault.rs](../crates/opca-core/src/services/vault.rs) — enumerates
    every CA-related item in a vault and serialises them into the JSON
    payload consumed by `backup`.
- [error.rs](../crates/opca-core/src/error.rs) — `OpcaError`, a single
  `thiserror` enum that every layer returns. Serialises as `{kind, message}`
  so the frontend can pattern-match error types.

---

## 1Password vault as the source of truth

OPCA stores ten logical kinds of item. Titles and field labels are fixed in
[constants.rs](../crates/opca-core/src/constants.rs).

| Item | Title | Kind | Purpose |
|---|---|---|---|
| CA | `CA` | Secure Note | CA certificate, private key, subject, validity, serial counters |
| Database | `CA_Database` | Document | SQLite dump of every tracked cert/CSR/CRL/VPN record |
| CRL | `CRL` | Document | Latest Certificate Revocation List; in batch mode, the first CRL of the current batch |
| OpenVPN | `OpenVPN` | Secure Note | DH params, TLS-auth static key, server config, and the named templates (canonical store; mirrored into the `openvpn_template` table for fast reads) |
| Certificate | `CRT_<serial>_<cn>` | Secure Note | One item per issued cert (key + cert + chain + type). Deleting a revoked or expired cert (`CertificateAuthority::delete_certificate`) archives it; see [Deleted certificates](#deleted-certificates) |
| External cert | `EXT_<cn>` | Secure Note | Imported certificates not signed by this CA |
| CSR | `CSR_<cn>` | Secure Note | Unsigned or awaiting-sign requests, with their private key. Deleting a pending CSR (`CertificateAuthority::delete_csr`) archives it |
| VPN profile | `VPN_<serial>_<cn>` | Document | Generated OpenVPN profile (`.ovpn`) — the template injected with the chosen cert's key/cert + CA + TLS-auth. The profile *record* (CN, title, template, serial, `generated`) is also written to the `openvpn_profile` table and persisted, so the Profiles list survives a restart. Serial pins it to a specific cert so a renewal (new serial) yields a distinct profile. A profile can be **registered without generating** (`generated = 0`, no document yet) and produced later via Regenerate; such rows surface as Needs Regen. Legacy profiles may still be titled `VPN_<cn>`. |
| DKIM | `DKIM_<domain>_<selector>` | Secure Note | DKIM key pair and metadata; the public key is published at `<selector>._domainkey.<domain>` |
| Lock | `CA_Lock` | Secure Note | Advisory lock for concurrent-write safety |

### Why a shadow SQLite database?

Listing and filtering certificates purely through `op` is slow and has no join
or index support. OPCA keeps a full SQLite mirror in memory, consults it for
every query, and re-serialises it to the `CA_Database` document whenever the
catalogue changes. The dump is keyed by a `download_fingerprint` so stale
local state is detected on reconnect.

The same mirror pattern backs DKIM keys, OpenVPN templates, and OpenVPN profile
records: the 1Password items remain canonical, but each is shadowed in a table
(`dkim_key`, `openvpn_template`, `openvpn_profile`) so list/detail views read
from SQLite instead of spawning `op`. On first read of an empty table the
command seeds it from 1Password (reconciling deletions); thereafter every
mutation upserts the row and calls `store_ca_database()` to persist. The OpenVPN
page is Profiles-first — a generated profile's record lands in the DB on create
(it previously lived only in memory and vanished on restart), and the template
dropdown is served from the mirror so it is populated immediately rather than
waiting on a lazy `op` fetch.

### Status classification vs. problem suppression

A certificate is always classified by its **true status**:
`process_ca_database` fills `certs_valid` / `certs_expires_soon` /
`certs_expires_warning` / `certs_expired` / `certs_revoked` from the cert's
validity dates alone. Two overlays then decide what counts as an *actionable
problem* — without changing that classification, so the list always shows the
real status.

**Supersession (automatic)** — a two-pass scan. The first pass collects, for
each CN, the highest-serial currently-valid cert (not expired, not revoked, not
about to be revoked). The second pass reclassifies an expired cert whose CN
matches such a serial into `certs_superseded` (with a `replacements:
HashMap<old_serial → new_serial>` entry) instead of `certs_expired`. This
catches any same-CN re-issuance — including a renewed/rekeyed predecessor once
it expires. Supersession is a runtime classification only; the DB rows aren't
modified. The first pass also exposes its result as `valid_cn_to_serial`
(CN → current valid serial), reused below for VPN profile status.

**VPN profile status (derived, never stored)** — `list_openvpn_profiles` runs
`process_ca_database` then calls `derive_vpn_profile_status` for each profile,
comparing the profile's pinned cert serial against `certs_revoked` /
`certs_expired` / `replacements` / `valid_cn_to_serial` / `certs_expires_soon`.
It returns one of `revoked` / `needs_regen` (with the replacement serial) /
`expired` / `expiring_soon` / `current` (precedence in that order). Because a
rekey/renew auto-ignores the old cert, the CN's current valid serial is already
the new one while the profile still pins the old — so `needs_regen` fires
immediately, before calendar expiry. `expiring_soon` is tested against the
pinned serial directly (the same `certs_expires_soon` set the certificate list
uses), so it surfaces even for an **ignored** cert — which `valid_cn_to_serial`
omits — matching how the cert list shows ignored-but-expiring certs. A row with
`generated = 0` (registered but not yet produced) also reports `needs_regen`,
against the CN's current valid serial. There is no cert→profile write coupling:
the status is computed fresh on every list load, so any cert change (revoke,
expire, renew, rekey, manual import) surfaces on the Profiles view without an
event system.

**Ignore (a "don't-notify" overlay)** — ignoring a cert **never changes its
status**. It records four audit columns (`ignored_at`, `ignored_by` =
`username@hostname` from the `whoami` crate, `ignored_reason` ∈ {`renewed`,
`rekeyed`, `manual`, `deleted`}, `ignored_note`) and adds the serial to the `certs_ignored`
overlay set. The cert keeps appearing in its real bucket — a still-valid ignored
cert is `Valid` (or `Expiring Soon`), an expired ignored cert is `Expired` —
and renders on the list with its true status badge plus an `ignored` chip. What
"ignored" buys is **no notification about problems**; the alert consumers
subtract the overlay:

- the dashboard's expiring/expired counts (and the expired action item) use
  `set.difference(&certs_ignored)`. The **Valid** count is the real number of
  certs that pass validation — `certs_valid + certs_expires_warning` (every
  non-expired, non-revoked cert, so it includes expiry-window and
  ignored-but-valid certs); Revoked stays real too; and
- the notification Lambda's query adds `AND ignored_at IS NULL`.

Two paths write the ignore: `renew_certificate_bundle` /
`rekey_certificate_bundle` auto-ignore the predecessor as soon as the
replacement is stored (`ignored_reason` = `renewed`/`rekeyed`, `ignored_note` =
`replaced by <new_serial>`, riding the same `store_ca_database` save — no extra
1Password calls); and the cert detail page's `Ignore` action (`ignored_reason`
= `manual`). An `Un-ignore` action clears all four columns.

### Deleted certificates

Delete is a soft delete. `delete_certificate` refuses the CA and any cert that
is not Revoked or Expired, so it can never bypass revocation. It archives the
item (`op item delete --archive`, tolerating a missing one), sets
`deleted_at` (schema v14) and, unless already ignored, `ignored_at` with
reason `deleted`, so the Lambda stops alerting with no change of its own. The
row stays because the CRL is built from revoked rows (`crl_entries`, which
also gives the stored CRL revoked count): removing an unexpired one
would silently un-revoke it. `query_all_certs` and `count_certs` skip deleted
rows (certificate list, bulk selection, CLI, dashboard total), while
`process_ca_database`, `query_cert` and `query_all_certs_including_deleted`
still see them, so the CRL, the dashboard's revoked count and VPN profile
status and type keep working.
In the app, `canDeleteCert` in
`api/certActions.ts` gates the kebab and bulk Delete; the CLI has
`opca cert delete -s <serial>`, or `-n <cn>` when exactly one of that CN's
certs is revoked or expired.

On the certs list (which defaults to the `Valid` filter), status-axis filters
match the true status: `Valid` includes valid-but-ignored certs, and an
`Expiring Soon` badge is shown for any cert in the warning window, ignored or
not. There are dedicated `Expiring Soon`, `Ignored`, and `Superseded` filters;
the `Expiring Soon` filter excludes ignored certs so it matches the dashboard's
expiring count. The same `Valid`/`Expiring Soon`/`Expired` rendering is shared
between the list and the cert detail page via the `CertStatusBadge` component.

### Pre-signed CRL batches

Off by default, per CA (`crl_batch_enabled` in `config`, schema v15; `opca
database config-set --conf crl_batch_enabled=true`). Off, `generate_crl` signs
one CRL valid for `crl_days`. On, it signs a batch so a key-less releaser (the
notification Lambda) can publish fresh CRLs while the desktop is closed:

- CRL *i* of N = 5 has `thisUpdate = T0 + i·7 d` and `nextUpdate = thisUpdate +
  10 d` (`CRL_BATCH_*` in `constants.rs`), numbered upward from the next CRL
  serial; the counter advances by N, so a re-sign numbers above the last batch.
- CRL 0 (`thisUpdate` = now) is stored as the `CRL` item and in
  `crl_metadata`, as a single CRL would be.
- The batch's T0, period, window, size and first number go in the `crl_batch`
  table. `CrlBatch::status(now)` derives the due CRL (greatest `thisUpdate` ≤
  now), signed-until (the last `nextUpdate`) and how many are unreleased.
  `opca crl info` shows them. Generating with batches off deletes the record.
- The batch is uploaded as one object, the PEM CRLs concatenated in number
  order, to `<private store>/pending-crl/crl-batch.pem`, replacing the last
  one whole. The upload happens inside `generate_crl`, after the `CRL` item and
  database are stored, and a failure is returned as `CrlBatchUpload`: an
  unuploaded re-sign would leave the pre-revocation batch being released.
  Revoking (app, bulk and CLI) regenerates, so it re-signs and uploads too; the
  app's error says whether regenerating or uploading failed. With no private
  store configured, generating refuses before signing anything.
- `rsync://` and `sftp://` stores need the `pending-crl/` directory to exist.

### AWS credentials

`s3://` stores and Route53 DKIM deployment need AWS credentials. These are
split across two homes, because the two halves have different owners:

| Setting | Home | Scope |
| --- | --- | --- |
| Store URIs, `ca_aws_region` | `config` table in the CA database | Shared — every operator of the CA |
| Which 1Password item holds the access key | `settings.json` (see below) | Personal — one operator, one machine |

The CA database lives in the shared vault, so anything stored there applies to
everyone. Several operators typically share one CA while each holds their own
AWS access key, so the credential *choice* cannot live there. It is instead
kept locally by [settings.rs](../crates/opca-core/src/settings.rs) at the
platform config directory (macOS: `~/Library/Application Support/opca/
settings.json`), keyed per account so an operator working across tenants keeps
a separate selection per tenant.

The key is the account's **`user_uuid`**, not the identifier the user supplied.
`op --account` accepts a shorthand, a sign-in address, an account UUID or a user
UUID for the same account, and the GUI and CLI pass different ones — keying on
the raw string gave one operator several entries, so a selection made in the GUI
was invisible to `opca aws show`. `account_key` resolves in two steps: match the
identifier against `op account list` (local, no sign-in, memoised), and failing
that ask `op account get --account <identifier>`, which resolves anything `op`
itself accepts — notably a shorthand, which `op account list` does not report.
When no account was given at all, `op whoami` says which one is signed in.
Anything that still resolves to nothing falls back to the lowercased string, so
resolution never fails, it only stops converging; an address shared by two
accounts is deliberately in that group, since `op --account` rejects it too.

Entries written under an older identifier are rekeyed when the file is read
(`migrate`, which puts every existing key back through the same resolution), so
nobody has to re-pick; the file itself is rewritten on the next save. Keying on
`user_uuid` rather than the tenant because the chosen item lives in a vault only
that user can read, and not on the address because a shared one names two
accounts.

Resolution is a plain `op item get <item_id> [--account <acct>]`, reading the
fields `access key id`, `secret access key`, and optionally `session token` and
`default region`. Items created by the 1Password AWS shell plugin (`op plugin
init aws`) use exactly these labels, so they work unchanged — but OPCA no
longer reads `~/.config/op/plugins/aws.json`. That file records a single
machine-global default with no notion of which tenant OPCA is connected to,
which broke outright when the first entry belonged to a different account than
the one OPCA was signed in to.

Region precedence is `ca_aws_region` → the item's `default region` field →
`ap-southeast-2`.

Surfaces: **CA → Stores** in the GUI (region field plus a per-user item
picker), and `opca aws list|show|use|clear` in the CLI. Selecting an item
validates it by reading it, so a mis-pick fails at selection rather than at the
next upload.

### Concurrent-writer safety

Any mutating operation goes through `VaultLock`:

1. Acquire — `op item create CA_Lock …` fails if a lock already exists. If it
   does, OPCA parses the holder metadata (email, hostname, acquired-at, TTL)
   and either waits, breaks a stale lock, or refuses the operation.
2. Perform the mutation through the command queue.
3. Flush the queue to 1Password.
4. Release — delete `CA_Lock`.

The frontend wraps write calls in `withLock()` in
[api/tauri.ts](../frontend/src/api/tauri.ts) so the lock lifetime always
matches a single logical operation.

`store_ca_database()` persists the SQLite dump to the canonical `CA_Database`
1Password document only. The slower **private-store** copy (e.g. the `s3://`
backup, which fetches AWS creds and PUTs) is *not* uploaded inline — that would
hold the `AppState.conn` mutex and stall reads (cert/profile lists). Instead
`withLock()` fires the `sync_private_store` command fire-and-forget after each
mutation: it snapshots the DB under a brief `conn` lock, then uploads in a
background task holding only `AppState.private_store_lock`, so reads stay
unblocked and the upload trails the screen refresh. The snapshot's SHA-256 is
compared against the last successful sync to skip no-op uploads. (The Database
page's manual `upload_ca_database` remains a synchronous, foreground sync.)

---

## Tauri shell (`opca-tauri`)

- [main.rs](../crates/opca-tauri/src/main.rs) — Tauri builder. Registers
  the `log`, `dialog`, `shell`, and `clipboard-manager` plugins; extends `PATH`
  on macOS so bundled `.app` builds can find Homebrew-installed `op`; pre-warms
  `op --version` so macOS AMFI/OCSP verification is cached before the first real
  call.
- [state.rs](../crates/opca-tauri/src/state.rs) — `AppState`, Tauri's
  managed singleton. Mutex-guarded fields:
  - `conn: Connection { op, ca }` — the live 1Password handle and the loaded
    `CertificateAuthority`. A single mutex makes connect/disconnect atomic
    with respect to in-flight operations. `ensure_ca()` lazily retrieves the
    CA from 1Password on first use; it and `init_ca` work on a clone of `op`
    and only drop it on success, so a failure (such as an empty vault) stays
    connected.
  - `vault_lock: VaultLock` — the current process's advisory lock handle.
  - `action_log: Vec<LogEntry>` — in-memory audit trail surfaced on the
    Database page's Activity Log. It belongs to the connection: cleared, with
    the preloaded key, whenever `replace_connection` swaps `conn` (connect,
    disconnect, vault restore).
  - `private_store_lock` / `last_private_store_sync` — serialise the background
    private-store upload (off `conn`) and skip it when the DB is unchanged (see
    Concurrent-writer safety).
  - `fresh_cert_pems` — one-shot cache of a just-issued certificate's PEM
    (keyed by serial), so the detail page can show a freshly renewed/rekeyed
    cert without re-reading its bundle from 1Password.
  - `preloaded_key` — the private key of the certificate open in a detail
    page (one slot, zeroised, keyed by item title, never a CA's), filled by
    the page's backfill so copying the key needs no second 1Password fetch.
    Cleared when the page unmounts (`forget_preloaded_key`) and whenever the
    CA is dropped (connect, disconnect, vault restore). Key exports take an
    optional passphrase and return encrypted PKCS#8.
- [commands/](../crates/opca-tauri/src/commands) — one module per
  feature area (`ca`, `cert`, `crl`, `csr`, `database`, `dkim`, `openvpn`,
  `vault`, `lock`, `connect`, `dashboard`, `files`, `logs`, `update`). Each
  module exposes `#[tauri::command]` async functions that deserialise DTOs,
  call into `opca-core`, and return serialisable results. DTO shapes are
  defined in [commands/dto.rs](../crates/opca-tauri/src/commands/dto.rs).

The shell is intentionally thin: no PKI logic lives here, only glue between
the webview and `opca-core`.

### Dev-only MCP server

The `mcp` cargo feature (on in `npm run tauri:dev`) compiles
[mcp/](../crates/opca-tauri/src/mcp) in, which serves an MCP endpoint on
`127.0.0.1:${OPCA_MCP_PORT:-8790}` behind a bearer token (`OPCA_MCP_TOKEN`, or
random), and writes `{url, token}` to `target/mcp.json` (0600). Combining
`mcp` with a release build is a `compile_error!`, so no shipped binary carries
it. The server comes from the private `lib-wiredai-rs` (`wiredai-mcp`, over
ssh); cargo resolves it even with the feature off, so CI loads a deploy key.

- **Read tools** — `app_status` and `list_certs` read `AppState` and never call
  `op` (not even `ensure_ca`).
- **UI tools** — `navigate`, `set_theme`, `resize_window`. The app is changed
  only through the UI under test.
- **DOM tools** — `query`, `wait_for` (read-only), `click`, `type`, `press`,
  from `wiredai-mcp`'s `dom` feature via `impl DomBridge for OpcaTools`.
  `query` reports every element matching a CSS selector (optionally filtered
  by visible text) with its form state, rect, whether it sits wholly in the
  viewport, and the overflow ancestor clipping it.

Everything except `resize_window` crosses a bridge: the server emits
`harness:request {id, op, args}` to the main window and awaits the matching
`harness:reply`, timing out after 10 s. The webview side,
[harness/bridge.ts](../frontend/src/harness/bridge.ts), handles `navigate`
and `set_theme` and hands the DOM ops to
[harness/domOps.ts](../frontend/src/harness/domOps.ts), vendored
byte-for-byte from the library (a Rust test compares it with
`wiredai_mcp::dom::OPS_TS`). Both are imported only under
`import.meta.env.DEV`, so they are absent from `frontend/dist`. `click`
dispatches pointerdown → mousedown → mouseup → click so outside-click dismissal
is exercised.

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

### Bulk command group

The `bulk_*` commands (`bulk_rekey_certs`, `bulk_renew_certs`,
`bulk_revoke_certs`, `bulk_delete_certs`, `bulk_ignore_certs`, `bulk_unignore_certs`, plus
`bulk_generate_openvpn_profiles` and `bulk_delete_openvpn_profiles`) each loop
the same `opca-core` method their single-cert sibling calls, taking one CA
borrow for the whole batch. The frontend wraps the single invocation in one
`withLock`, so a batch of N items costs **one** vault-lock cycle rather than N.
Per-item failures are collected into a result vector (`BulkCertResult` /
`BulkProfileResult`) and the loop continues; the command-level `Err` is reserved
for the CA being unavailable. Each underlying `*_certificate*` / generate call
still flushes via `store_ca_database()`, so a batch of N does N flushes —
accepted for now; batching the flushes is future work.

---

## Frontend (`frontend`)

A single-page SolidJS app. Key conventions:

- [App.tsx](../frontend/src/App.tsx) routes based on `vaultState`
  (`valid_ca` / `empty_vault` / `invalid_ca`) returned by `connect`. Empty
  vaults are steered to CA initialisation; broken vaults to the dashboard
  with an error banner.
- [pages/Connect.tsx](../frontend/src/pages/Connect.tsx) picks the vault
  from previously-used logins (localStorage) or the account's vaults, and the
  account from `list_accounts` — `op account list`, which reads local CLI
  config and so works signed out. Both dropdowns run before there is a
  connection, alongside `check_op_cli`; a failure just hides the account
  picker. The vault list is `list_vaults` (`op vault list`, which needs a
  sign-in), fetched when the dropdown opens and kept per account value, so
  typing never lists and a failure retries on the next open. The account field
  takes the sign-in address, falling back to that account's UUID when two configured
  accounts share an address (see `accountValue` in
  [api/accounts.ts](../frontend/src/api/accounts.ts)) — `op --account`
  cannot resolve a shared address. Which form it sends is purely an `op`
  concern; `settings.rs` canonicalises them all (see AWS credentials above).
  Its create mode calls `create_vault` (core `create_vault_standalone`), which
  needs no connection and refuses a name or ID already in `op vault list`
  because `op` allows duplicate names, then connects and lands on `/ca`, where
  the empty vault opens the Init tab. `VaultPicker` creates vaults the same
  way, in the connected account, and so does `opca ca init --create-vault`
  before it connects.
- [api/](../frontend/src/api) — one file per feature, each a typed
  wrapper around `tauriInvoke` from
  [api/tauri.ts](../frontend/src/api/tauri.ts). `tauriInvoke` normalises
  the rejection to an `Error` and tracks the in-flight operation — kept
  as a stack in [stores/operation.ts](../frontend/src/stores/operation.ts)
  (the side-nav shows the most recent op and never blanks mid-flight, and a
  finishing background task can't clear a running foreground one). `withLock()`
  wraps any mutation in acquire/release calls and then fires the background
  `sync_private_store`.
- [stores/](../frontend/src/stores) — small reactive stores (`app`,
  `operation`, `theme`, `update`). No global state framework.
- [pages/](../frontend/src/pages) mirror the Tauri command modules
  roughly 1-to-1.
- [components/](../frontend/src/components) — reusable UI. Mutating
  actions on the certificate list/detail and the OpenVPN Profiles list share a
  per-row `KebabMenu`; Ignore / Revoke / Send-to-Vault are self-contained
  `Modal` dialogs reused across those pages.

### Styling tokens

The CSP forbids static inline styles, so all styling lives in
[styles/](../frontend/src/styles) and refers to tokens rather than
literals. Colours that differ by theme are defined in
[styles/theme.ts](../frontend/src/styles/theme.ts) (`darkTheme` /
`lightTheme`), which the `theme` store writes onto `:root`, along with a
`data-theme` attribute that sets `color-scheme` so native controls follow the
app's theme rather than the OS appearance. Everything that
does not vary by theme is a static `:root` variable in
[styles/global.css](../frontend/src/styles/global.css): status tints and
edges derived with `color-mix` (`--{success,error,warning,caution,neutral,link}-{tint,edge}`),
`--radius-*`, `--shadow-*`, `--overlay`, `--font-mono` and the stacking order
`--z-sticky` < `--z-modal` < `--z-popover`. New styles use these; a raw hex or
pixel radius in a component stylesheet is a regression.

### Popovers

Anything that floats over the page — the row `KebabMenu`, `VaultPicker`,
`VpnClientPicker` and Connect's saved-login and account pickers — renders
through [components/Popover.tsx](../frontend/src/components/Popover.tsx).
It portals to `body` at `--z-popover`, so it escapes the `overflow` of a
`.modal-dialog` or the page, and positions itself with the pure
[utils/placePopover.ts](../frontend/src/utils/placePopover.ts): below the
anchor, else above, else on the larger side with a capped height, clamped
8px inside the window horizontally. It closes on outside mousedown, Escape,
outside scroll or resize, hands focus back to the anchor if it held it, and
handles arrow / Home / End between items. Clicks stop at its root and Escape
is captured on `window`, so a popover in a table row or a `Modal` triggers
neither the row nor the dialog. List rows use `PopoverOption`
(`role="option"`, Enter / Space to activate) and the shared `.popover-option`
styles in `styles/components/popover.css`.

### Publishing to a store

Generating a CRL, re-signing the CA and mutating the database all leave the
copy in the store stale — the backend does not upload as a side effect. That
follow-up is one mechanism, not three:
[utils/publishFlow.ts](../frontend/src/utils/publishFlow.ts)'s
`createPublishFlow({ upload, success, outcome })` owns the in-flight flag and
the offer-to-upload state, and reports through the page's existing banner
controller rather than a second one — the CRL page narrates generate *and*
upload in one place. [components/UploadPrompt.tsx](../frontend/src/components/UploadPrompt.tsx)
renders the amber prompt from it. Same state-here / rendering-there split as
`createActionResult` and `ResultBanner`.

### When a page throws

Resource getters rethrow on read, so a failed load would otherwise blank the
window. [components/RouteErrorBoundary.tsx](../frontend/src/components/RouteErrorBoundary.tsx)
wraps the route outlet *inside* the layout, so the sidebar and header stay
usable and the user can navigate away — which recovers on its own, because the
router rebuilds the outlet. "Try again" is for retrying in place. This catches
render-time throws only; failures inside async event handlers, which is where
nearly every command lives, are reported by the page through its result banner.

### Confirming destructive actions

Anything irreversible goes through a `Modal`, never a bare button. `ConfirmDialog`
is the generic gate: it owns the acting/error state, renders a `danger` confirm,
closes only on success, and takes a `children` slot plus a `canConfirm` predicate
for callers that need their own field. Bulk cert and OpenVPN actions use it with
a reason field; `ResignCaDialog` uses it with a validity-days field;
`RevokeCertDialog`, `DeleteCertDialog` and `IgnoreCertDialog` wrap it with a `certLabel` message.
Every wrapper is prop-passing only, so `ConfirmDialog`'s own test owns the
shared behaviour and each wrapper's test asserts just its wiring.

Re-signing the CA earns a confirmation despite keeping the key, subject and
serial (so issued certificates still chain): `re_sign_ca` overwrites the vault
item with `StoreAction::Edit` and takes no snapshot, so **opCA cannot undo it** —
recovery means 1Password's own item history or a vault restore. It also does not
publish, so the CA page offers to upload afterwards, the same way the CRL page
does after Generate.

### Reporting the outcome of an action

The operation indicator above is strictly *in-flight* — it clears the moment a
command returns and carries no terminal state. Actions that change the vault
therefore report their own outcome through
[utils/actionResult.ts](../frontend/src/utils/actionResult.ts):
`createActionResult()` holds one `{summary, error}` result, auto-clears a
success after a few seconds, and keeps a failure until dismissed so the error
stays readable. It owns state only; three renderers in
[components/ResultBanner.tsx](../frontend/src/components/ResultBanner.tsx)
share one `BannerShell`:

| Renderer | Used for |
| --- | --- |
| `ActionResultBanner` | one action — green, or red with the error beneath |
| `ActionResultLine` | the CA tabs, whose established idiom is a line under the form |
| `ResultBanner` | bulk runs — a neutral `n succeeded` count plus per-item failures |

A bulk count is reported neutrally rather than green: a partially-failed run
should not read as simply "good".

Reporting is one half; running is the other.
[utils/action.ts](../frontend/src/utils/action.ts)'s
`createAction(outcome)` owns an action's in-flight flag and the
clear/try/report dance around its body. Take one per button so `busy()` gates
just that button, or share one across a group that is enabled and disabled
together (the certificate detail page's kebab). The success headline is built
from whatever the body returned, and the failure headline is resolved after the
body too, so it can say how far a partial failure got — "generated, but the
upload failed". `run()` never throws, so whatever used to sit in `finally` is
simply the code after the await. `createPublishFlow` is built on it.

An error that belongs to the page rather than to one action is rendered by
[components/PageError.tsx](../frontend/src/components/PageError.tsx). It
coerces whatever it is given and renders nothing for null, undefined or an
empty string, so a resource error goes straight in with no `<Show>` and no
`String()` around it. An error under a form (the CA tabs, the create/import
pages) is the same component with `placement="form"`, which swaps the page
spacing for the form's.

Two cases deliberately do **not** use this. Rekey and renew navigate to the new
serial, where `CertInfo`'s `.fresh-banner` reports the outcome from
`?freshFrom=&op=` search params — deliberately URL-derived so it survives a
reload. `CertInfo`'s `.ignored-banner` and `.superseded-banner` describe
persistent server state, not an action result, so they are not dismissable. A
result that must cross a route change (deleting a DKIM key navigates to the
list) is handed over in router `state`, which is transient by design.

---

## Lifecycle of a typical operation

1. User clicks **Revoke** on a certificate in the webview.
2. The SolidJS page calls `revokeCert()` in `api/certs.ts`.
3. `withLock("revoke_cert", …)` acquires `CA_Lock` via `acquire_lock`.
4. The page invokes `revoke_cert` — a `#[tauri::command]` handler.
5. The handler calls `AppState::ensure_ca()` to get (or lazily load) the CA.
6. `CertificateAuthority::revoke_certificate` marks the cert revoked in the
   SQLite DB and stores `CA_Database`; the handler then calls `generate_crl`,
   which signs a new CRL (next CRL Number, Authority Key Identifier) and stores
   the `CRL` document and the database. Bulk revoke regenerates once after the
   batch. Uploading the CRL to the public store stays a separate action, as in
   the CLI; in batch mode the re-signed batch goes to the private store before
   the handler returns (see [Pre-signed CRL batches](#pre-signed-crl-batches)).
7. Each store becomes an `op` CLI invocation.
8. The handler serialises the result; the frontend updates its view.
9. `withLock` releases `CA_Lock` in its `finally` clause, then fires
   `sync_private_store` (fire-and-forget) to back the DB up off the lock.
10. An entry lands in `action_log` for display on the Activity Log.

If any step fails, the error propagates as an `OpcaError` through every
layer and is surfaced in the UI via `setAppState("error", …)`.

---

## Testing

- **Unit** — `cargo test -p opca-core`. Uses `MockRunner` to feed canned `op`
  output; no network, no `op` binary required.
- **Tauri commands** — `cargo test -p opca-tauri`. Under `cfg(test)`
  `state::Runner` is core's `MockRunner` (via core's `test-support` feature),
  and `test_harness::Harness` builds a `tauri::test::mock_builder` app over a
  loaded in-memory CA, invokes commands over IPC with the frontend's argument
  names, and exposes the recorded `op` calls, action log and emitted events.
- **Integration** — `OPCA_INTEGRATION_TEST=1 cargo test -p opca-core --test
  op_integration`. Exercises the low-level `Op` wrapper against a real `op`
  session and test vault (`OPCA_TEST_VAULT`, optionally `OPCA_TEST_ACCOUNT`).
- **End-to-end** — `OPCA_INTEGRATION_TEST=1 cargo test -p opca-core --test e2e
  -- --test-threads=1`. Runs the full CA lifecycle (init → issue → renew/rekey
  → revoke → CRL → backup/restore) against a throwaway vault it creates and
  deletes; needs an `op` session (set `OPCA_TEST_ACCOUNT`) and a `Private` vault
  to bootstrap. Tests are ordered (`t01`…`t90`) and share state, so they run
  single-threaded.
- **Running app** — with `npm run tauri:dev` up and a CA loaded, `npm run
  harness:walk` drives the window through the dev MCP server
  ([harness/](../harness)) by selector, asserting on layout numbers in
  both themes. It prints PASS/FAIL/SKIP and exits non-zero on a failure; it
  never selects a mutating menu item.
- **GUI flow** — with the dev app up and disconnected, `npm run harness:flow`
  starts a CA in a new `opca-flow-*` vault through the connect screen, then
  issues, revokes and deletes a certificate through the Certs page, asserting on
  the DOM and `list_certs`; teardown forgets the saved login and deletes that vault.

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
- In batch mode, each CRL generation also uploads the pre-signed batch to the
  private bucket at `pending-crl/crl-batch.pem`.

The Lambda never talks to 1Password and never touches private keys — it only
needs the already-published database dump, CA certificate, and CRL.

### What it checks

[`lambda_handler`](../notification/aws_lambda.py) orchestrates three S3
downloads and calls `run_tests`, which reports on:

- **CA database freshness** — age of the S3 object vs. the `DAYS` threshold.
- **Issued certificates** — SQL query against the `certificate_authority`
  table for any non-revoked, non-ignored cert expiring within `DAYS`
  (`ignored_at IS NULL` excludes renewed/rekeyed predecessors).
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

The deployed Lambda authenticates with its execution role. For local runs,
[notification/aws_lambda_test.py](../notification/aws_lambda_test.py) sources
credentials the same way OPCA does — `op item get` against the item selected in
**CA → Stores** — so no AWS CLI is needed. Source `environment.sh` first: the
handler reads its configuration from the environment at import time.
Offline unit tests live in
[notification/test_aws_lambda.py](../notification/test_aws_lambda.py)
(`python -m pytest notification/test_aws_lambda.py`, Python ≥ 3.12).

The Lambda stays in Python because it is a tiny, infrequent cron job with no
1Password dependency — keeping it separate from the desktop app means the
user's 1Password session is not part of the monitoring loop.
