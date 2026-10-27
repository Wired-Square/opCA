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

Two more crates make up the ACME broker, which runs on a host of its own (see
[ACME broker](#acme-broker-opca-acme-broker)):

| Component | Role |
|---|---|
| [opca-acme-api](../crates/opca-acme-api) | The versioned wire types of the API between opCA and a broker. serde only; both ends build against it. |
| [opca-acme-broker](../crates/opca-acme-broker) | The broker daemon (`opca-acme-broker`) and its command line (`opca-acme`): holds a subordinate CA, pairs with opCA, runs step-ca. |

---

## Core library (`opca-core`)

Organised by concern under [src/](../crates/opca-core/src):

- [op.rs](../crates/opca-core/src/op.rs) — opCA's side of `wslib-1password`,
  which runs `op`: `connect` (sign in, then open the CA vault, whose `Vault`
  names itself by id on every call), the duplicate-name refusal for new vaults,
  `assign` for `DEFAULT_OP_CONF` labels, and `put_document`/`put_item`, which
  edit and create only when there is nothing to edit. The crate's `Error` maps
  into `OpcaError` in [error.rs](../crates/opca-core/src/error.rs). Item creates
  send their values as a JSON template on stdin; edits still pass them in argv.
  Its `ShellRunner` (the default runner of its `Op` and `Vault`) makes a call
  once more when 1Password refuses it as racing another write (409), which it
  does only to a write that did not land.
- [vault_lock.rs](../crates/opca-core/src/vault_lock.rs) — advisory lock
  implemented as a 1Password Secure Note (`CA_Lock`). `op` never refuses a
  duplicate title, so each acquirer creates its own lock and the one 1Password
  created first wins; stale locks past TTL are broken automatically.
- [crypto/](../crates/opca-core/src/crypto) — key generation, CRL/DKIM/
  OpenVPN helpers, and PKCS#12 packaging via the `openssl` crate.
- [services/](../crates/opca-core/src/services):
  - [ca.rs](../crates/opca-core/src/services/ca.rs) — the
    `CertificateAuthority` struct. Orchestrates init, sign, revoke, renew,
    rekey, CRL generation, and upload. This is the capstone API the Tauri
    layer calls into. Issuing and CRLs go through `wslib-crypto-ca` (from the
    private `wired-square` registry) on the `rustls-openssl` provider:
    `sign_certificate` verifies the CSR, builds a `Profile` per `CertType`
    (`profile_for`) and calls `Authority::issue`; `build_crl` calls
    `Authority::revocation_list`, which writes the Authority Key Identifier
    before the CRL Number. CRL metadata is read from PEM with `CrlView`
    (`parse_crl_metadata`; the CRL inspector calls `crl_metadata` on its own
    view), its issuer
    kept in OpenSSL's one-line form (`CN=…, C=…, emailAddress=…`) through
    `name_attributes`. A SHA-1-signed CSR can be read but not signed: the
    provider has no SHA-1. `crl_to_text` stays on `openssl-sys`
    (`X509_CRL_print`).
  - [ca/subordinate.rs](../crates/opca-core/src/services/ca/subordinate.rs)
    — signing, renewing, revoking and listing name-constrained subordinate CAs
    (see [Subordinate CAs](#subordinate-cas)).
  - [ca/operator.rs](../crates/opca-core/src/services/ca/operator.rs) and
    [acme_broker/](../crates/opca-core/src/services/acme_broker) — the
    operator identity and opCA's client for its ACME brokers (see
    [ACME broker client](#acme-broker-client)).
  - [cert.rs](../crates/opca-core/src/services/cert.rs) —
    per-certificate bundle operations (build, sign, import/export, inspect).
    `KeyAlgorithm` (`ec-p256`, `ec-p384`, `rsa-2048`, `rsa-4096`) picks the key,
    generated by `wslib_crypto::KeyAlgorithm::generate` and loaded into an
    `openssl` `PKey` from PKCS#8 (DKIM keys stay RSA on `openssl`);
    `CertType::default_key_algorithm` gives EC P-256 for leaves, EC P-384 for the
    CA and RSA 2048 for Apple developer CSRs, and a rekey keeps the existing
    family unless given an algorithm (`rekey_cert`, `bulk_rekey_certs` and
    `opca cert rekey --key` take one). CSRs are built by
    `wslib_crypto_ca::build_csr`, the `openssl` key passed as a
    `wslib_crypto::Signer` (`signer_of`, via PKCS#8); the CA's self-sign and
    re-sign stay on the `openssl` crate. Signatures use SHA-384 for P-384 keys
    and SHA-256 otherwise (`signing_digest` on the `openssl` side), and
    `keyEncipherment` is only set on RSA leaves.
  - [san.rs](../crates/opca-core/src/services/san.rs) — Subject
    Alternative Names: `SubjectAltName` (DNS, IP, email, URI) parses and
    validates user input, and `of_certificate` / `of_csr` read them back from
    the extension (`of_csr` through `wslib_crypto_ca::CsrView`). The frontend's `utils/san.ts` mirrors its parsing rules.
  - [openvpn.rs](../crates/opca-core/src/services/openvpn.rs) — OpenVPN
    client-profile templates, stored canonically in the `openvpn_template`
    table, plus the starter template and the one-time move of templates off
    the 1Password `OpenVPN` item (see *OpenVPN templates* below).
  - [database/](../crates/opca-core/src/services/database) — in-memory
    SQLite (`rusqlite`) holding the CA config and every issued/external
    certificate, CSR, CRL metadata record, CRL batch record, and OpenVPN
    template/profile. The whole DB is serialised and persisted as the
    `CA_Database` document in 1Password. A schema-version field drives
    automatic, forward-only migrations (currently v17). A dump that fails to
    parse or never reaches its `COMMIT` (truncated) is rejected as
    `OpcaError::DatabaseUnreadable`.
  - [local_backup.rs](../crates/opca-core/src/services/local_backup.rs) —
    rolling local copies of the SQL dump, written by `store_ca_database()` on
    every save while `local_backup_enabled` (a [settings.rs](../crates/opca-core/src/settings.rs)
    field, default on). Stored under the settings directory at
    `backups/<account key>/<vault id>/ca-database-<UTC timestamp>.sql`, keyed by
    the same canonical account key as the AWS credential selection; the first
    line is a SQL comment recording the account key, vault name and vault ID.
    Each is written whole and owner-only through `wslib-file-atomic`.
    Identical consecutive dumps are skipped and the newest 30 are kept. The
    timestamp in the filename (not the mtime) is the backup's age.
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
    calls for DKIM TXT record deployment, the value split into 255-octet
    quoted strings by `wslib_dns::txt::{split, quote}`, and the DKIM DNS check
    (`check_dkim_record`), which looks the record up through `wslib-dns` so
    NXDOMAIN/NODATA (not published) stay apart from SERVFAIL, REFUSED or a
    timeout (`OpcaError::Dns`).
    Published keys are read with `wslib-dns-mail`'s DKIM parser and compared
    decoded.
  - [backup.rs](../crates/opca-core/src/services/backup.rs) — encrypted
    file format: 4-byte magic `OPCA` + version + 16-byte salt + 12-byte
    nonce + 16-byte GCM tag + AES-256-GCM ciphertext. Key derivation is
    PBKDF2-HMAC-SHA256, 600 000 iterations. Plaintext never touches disk.
  - [vault.rs](../crates/opca-core/src/services/vault.rs) — enumerates
    every CA-related item in a vault and serialises them into the JSON
    payload consumed by `backup`. `CA_Lock` is left out of a backup and
    skipped on restore.
- [error.rs](../crates/opca-core/src/error.rs) — `OpcaError`, a single
  `thiserror` enum that every layer returns. Serialises as `{kind, message}`
  so the frontend can pattern-match error types.

---

## 1Password vault as the source of truth

OPCA stores eleven logical kinds of item. Titles and field labels are fixed in
[constants.rs](../crates/opca-core/src/constants.rs).

| Item | Title | Kind | Purpose |
|---|---|---|---|
| CA | `CA` | Secure Note | CA certificate, private key, subject, validity, serial counters |
| Database | `CA_Database` | Document | SQLite dump of every tracked cert/CSR/CRL/VPN record |
| CRL | `CRL` | Document | Latest Certificate Revocation List; in batch mode, the first CRL of the current batch |
| OpenVPN | `OpenVPN` | Secure Note | DH params, TLS-auth static key and server config. Templates live in the `openvpn_template` table; older versions kept them here as `template.<name>` fields (see *OpenVPN templates*) |
| Certificate | `CRT_<serial>_<cn>` | Secure Note | One item per issued cert (key + cert + chain + type). Deleting a revoked or expired cert (`CertificateAuthority::delete_certificate`) archives it; see [Deleted certificates](#deleted-certificates) |
| External cert | `EXT_<cn>` | Secure Note | Imported certificates not signed by this CA |
| CSR | `CSR_<cn>` | Secure Note | Unsigned or awaiting-sign requests, with their private key. Deleting a pending CSR (`CertificateAuthority::delete_csr`) archives it |
| VPN profile | `VPN_<serial>_<cn>` | Document | Generated OpenVPN profile (`.ovpn`) — the template injected with the chosen cert's key/cert + CA + TLS-auth. The profile *record* (CN, title, template, serial, `generated`) is also written to the `openvpn_profile` table and persisted, so the Profiles list survives a restart. Serial pins it to a specific cert so a renewal (new serial) yields a distinct profile. A profile can be **registered without generating** (`generated = 0`, no document yet) and produced later via Regenerate; such rows surface as Needs Regen. Legacy profiles may still be titled `VPN_<cn>`. |
| DKIM | `DKIM_<domain>_<selector>` | Secure Note | DKIM key pair and metadata; the public key is published at `<selector>._domainkey.<domain>` |
| Lock | `CA_Lock` | Secure Note | Advisory lock for concurrent-write safety |
| Operator | `CA_Operator` | Secure Note | The EC P-256 key opCA presents to its ACME brokers, made on the first broker call (see [ACME broker client](#acme-broker-client)) |

### Why a shadow SQLite database?

Listing and filtering certificates purely through `op` is slow and has no join
or index support. OPCA keeps a full SQLite mirror in memory, consults it for
every query, and re-serialises it to the `CA_Database` document whenever the
catalogue changes. The dump is keyed by a `download_fingerprint` so stale
local state is detected on reconnect.

The same mirror pattern backs DKIM keys and OpenVPN profile records: the
1Password items remain canonical, but each is shadowed in a table (`dkim_key`,
`openvpn_profile`) so list/detail views read from SQLite instead of spawning
`op`. On first read of an empty table the command seeds it from 1Password
(reconciling deletions); thereafter every mutation upserts the row and calls
`store_ca_database()` to persist. The OpenVPN page is Profiles-first — a
generated profile's record lands in the DB on create (it previously lived only
in memory and vanished on restart).

### OpenVPN templates

Templates are not secret — they hold `op://` references that `op inject`
resolves when a profile is generated — so the `openvpn_template` table is their
only store, and the TLS-auth key, DH parameters and server settings stay on the
`OpenVPN` item. Older versions kept templates as `template.<name>` fields on that
item. `config.openvpn_template_import` (v16) tracks moving them, per CA:

1. **Not imported** — the first template operation (list, get, save, delete,
   generate, setup; app or CLI) copies the item's templates into the table,
   overwriting same-named rows, since the item was canonical until then. Every
   template operation imports first, so a write can't later be overwritten.
2. **Awaiting cleanup** — set when the import found templates. The app's
   OpenVPN › Templates tab confirms the import, re-checking that every template
   on the item is in the table (copying any an older client added since,
   without overwriting the table's copy), and asks to **Archive** or **Keep**
   them. Archive copies the fields to a new `OpenVPN_Templates_<timestamp>`
   Secure Note, archives that note (1Password archives whole items, and the
   `OpenVPN` item can't be archived as it holds the keys), then removes the
   fields from `OpenVPN` — in that order, so a failure never loses a template.
   Keep leaves them for older clients.
3. **Settled** — after either choice, or when there was nothing to import.
   Older clients still read and write the item's fields, so their template edits
   aren't seen by this version.

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
- The Lambda releases the due CRL (see *Lambda notification*). OpenVPN servers
  pull the published CRL with
  [contrib/openvpn-crl-fetch.sh](../contrib/openvpn-crl-fetch.sh); operator
  setup (IAM, `PENDING_CRL_KEY`, systemd/cron) is in
  [crl-batches.md](crl-batches.md).
- In the app, the CA page's Stores tab has the toggle; `update_ca_config`
  refuses turning it on without a private store (`check_crl_batch_update`, which
  `opca database config-set` shares; `generate_crl` refuses with the same error). `get_crl_info`, `backfill_crl`, `generate_crl` and
  `get_dashboard` carry `crl_batch_enabled` and a `crl_batch` status (number
  range, due CRL, signed until, unreleased of N, `low_cover` under
  `CRL_BATCH_LOW_COVER` = 2), only while batches are on: the Lambda ignores a
  leftover record once they are off. The CRL page shows it; the dashboard shows
  a CRL Batch tile and judges CRL expiry (warning and action item) by its
  signed-until rather than CRL 0's `nextUpdate`.

### Subordinate CAs

A subordinate CA (`CertType::SubordinateCa`, `subordinateca`) is signed from a
CSR made where its key lives (an ACME broker host, or plain step-ca by hand),
so the key never passes through opCA. `sign_subordinate` takes the CSR and a
list of permitted domains, which `permitted_domains` lowercases and dedupes,
refusing wildcards, IP literals and anything not a DNS name. The profile
(`profile_for` plus the domains) is `CA:TRUE, pathlen:0` and keyCertSign +
cRLSign (both critical), `serverAuth` (not critical: a critical EKU on a CA
breaks some verifiers), critical name constraints permitting a DNS subtree per
domain and excluding `0.0.0.0/0` and `::/0`, and the CA's CRL and issuer URLs.
The CN comes from the CSR. Its SANs are never copied, and a CSR whose SANs or
host-like CN fall outside the domains is refused, after its signature is
verified and before a serial is spent. The lifetime is 90 days
(`SUBORDINATE_CA_DAYS`) unless asked, and one that would outlive the root is
refused rather than clamped. The Apple 825-day rule does not apply.
`issue_certificate` refuses the type, so the generic CSR sign and the
certificate list's Renew and Rekey can't make a subordinate without
constraints.

Each subordinate has a row in the `brokers` table (schema v17): its current
`subordinate_serial`, the broker's `url` and `pinned_key` (both `NULL` for one
signed by hand), `permitted_domains` as JSON, `state` (`active` / `revoked`),
`last_contact`, and `created_at` / `updated_at`. Expiry and CN are read from
the certificate row by serial, not stored twice. `renew_subordinate` signs a
fresh CSR for the row's domains and moves the row to the new serial. Different
domains need `change_domains`, so a renewal never widens on its own. The old
certificate stays valid and is auto-ignored as `renewed`, as a renewed leaf is.
`revoke_certificate` marks the row of the subordinate it revokes, so revoking
from the certificate list does too; `revoke_subordinate` goes through it, and
its callers regenerate the CRL as after any revoke.

Surfaces: `opca subordinate sign|renew|revoke|list` (each write under the vault
lock), the Tauri commands `sign_subordinate`, `renew_subordinate`,
`revoke_subordinate` and `list_subordinates`, and the CSR page's Sign tab,
which offers Subordinate CA with a permitted-domains field. `CertDetail`
carries `name_constraints` (read with `CertificateView::name_constraints`
once the backfill has the PEM), shown on the certificate page.

When the key lives on an ACME broker, the broker makes the CSR and pairs with
opCA to receive the chain: see [ACME broker client](#acme-broker-client) for
opCA's side and [ACME broker](#acme-broker-opca-acme-broker) for the daemon.

### ACME broker client

[acme_broker/](../crates/opca-core/src/services/acme_broker) is opCA's client
for the broker API, shared by the app and the CLI. `BrokerClient` speaks
HTTP/1.1 (hyper over tokio-rustls) to an `Endpoint`: the host and port, and
the API key's SPKI SHA-256, pinned through `wslib_tls::Outbound`. The pin comes
from the pairing URI while enrolling and from `brokers.pinned_key` after. Each
call is capped at 15 s, and fails as a `BrokerError`: `Unreachable`, `WrongKey`
(the pin didn't match), `Refused` (the broker's `ErrorBody`), `Status` or
`Malformed`. Each successful call to an enrolled broker stamps
`brokers.last_contact`.

**Operator identity.** Once enrolled, a broker admits only a client
certificate that chains to the root and carries the key it pinned at
enrolment. `CertificateAuthority::operator`
([ca/operator.rs](../crates/opca-core/src/services/ca/operator.rs)) reads
that key from the `CA_Operator` item, creating it on first use, so a CA with
no brokers never gains the item. It then issues a client certificate for it
from the root: the VpnClient profile (clientAuth only), CN `opCA operator`,
valid for a day and backdated 5 minutes, with a random serial. The certificate
isn't recorded in the database and spends no serial. The broker pins the key,
so the certificate can be minted again each session.

**Enrolment** (`enrol.rs`). `parse_pairing` reads the `opca-enrol://` string
and `fetch_offer` makes `GET /v1/enrolment` over the pinned connection, so a
wrong pin fails before the code is sent. The offer (host, CSR, configured
domains, versions) is shown, and `enrol_broker` takes it back with the
operator's domains. It fetches the offer again and refuses if it changed. The
broker's own domains, when it has any, must match any the operator gave, in
any order; otherwise the operator's are used. It signs the CSR with
`sign_subordinate`, recording `url` and `pinned_key` in the same store, then
`POST`s the code, the chain, the operator's pin and the issuance terms
(30-day leaves, at most 45, over http-01, dns-01 and tls-alpn-01). A row with a `url` but no `last_contact` is signed but
not delivered. Enrolling again with the same pairing string resends that
chain rather than signing twice. It refuses if the broker's key or domains
have changed since ("revoke it first"), or if the broker already took it.

**Renewal** (`renew.rs`). `renew_broker` calls `GET /v1/status` and
`POST /v1/csr`, signs the fresh CSR with `renew_subordinate`, and
`PUT /v1/chain`s it with the broker's current issuance config. It answers a
`Renewal`:

- `Renewed`;
- `DomainsChanged`: the broker now asks for other domains, and nothing was
  signed. Renewing with `change_domains` confirms them;
- `Unreachable`: nothing was signed;
- `NotDelivered`: signed and recorded, but the push failed. The next renewal
  signs afresh, and the undelivered certificate is auto-ignored as renewed;
- `Failed`.

`renew_all_brokers` renews every active broker with a `url` and reports each,
so an unreachable one is never skipped silently. Renewal is an explicit
action, not part of CRL generation.

**Revoke.** `revoke_broker` revokes the subordinate through the root
(`revoke_subordinate`), then `POST /v1/revoke`s. The revocation stands whether
or not the broker answers (`BrokerNotice::Told` / `NotTold`), and revoking an
already revoked row only tells the broker again, which is how an unreachable
broker is retried. The caller regenerates the CRL, as after any revoke.

**Concerns** (`concern.rs`). `concerns` flags an active broker with a `url`
whose subordinate expires within 30 days, whose `last_contact` is older than
35 days, or which is signed but not delivered. The dashboard tile, the ACME
Servers page and `opca broker list` use it, and the Lambda applies the same
thresholds (see [What it checks](#what-it-checks)).

Surfaces:

- **Tauri** — [commands/broker.rs](../crates/opca-tauri/src/commands/broker.rs):
  `fetch_broker_offer`, `enrol_broker`, `list_brokers`, `broker_status`,
  `renew_broker`, `renew_all_brokers` and `revoke_broker`. The connection mints
  the operator on the first broker call and keeps it (`Connection::operator`),
  minting another after 20 hours. A reconnect drops it. Every command but the
  offer and the list runs under `withLock`, status included, since it stamps
  `last_contact` and stores the database. `revoke_broker` regenerates the CRL
  as the certificate revoke does.
- **Frontend** — [pages/AcmeServers.tsx](../frontend/src/pages/AcmeServers.tsx)
  (`/acme`, "ACME Servers" in the sidebar) lists brokers with a `url`: state,
  domains, subordinate expiry, last contact and concerns. Enrol Broker opens
  [EnrolBrokerDialog](../frontend/src/components/EnrolBrokerDialog.tsx) (paste,
  review the offer, confirm), and Renew All, per-row Status, Renew and Revoke
  sit beside it. A `DomainsChanged` outcome offers Confirm and Renew. The
  dashboard's ACME Servers tile shows while there is an active broker, and
  lists the flagged ones. Subordinates signed by hand stay on the CSR page.
- **CLI** — [commands/broker.rs](../crates/opca-cli/src/commands/broker.rs):
  `opca broker enrol <pairing> [--domain …] [--yes]` (refuses before prompting
  when neither the broker nor `--domain` gives domains), `list`,
  `status <id>`, `renew <id> [--change-domains]` or `renew --all` (non-zero
  unless every broker renewed), and `revoke <id>` (revokes, regenerates and
  prints the CRL, then tells the broker). Writes run under the vault lock.

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
a separate selection per tenant. It is replaced whole and owner-only
(`wslib-file-atomic`).

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

1. Acquire — create a `CA_Lock`, then list every item of that title and read
   each rival with `op item get`. The lock with the earliest server
   `created_at` wins, then the lowest item id (by the holder's `acquired_at`
   when a creation time is missing or unreadable); a rival ahead of ours that
   is past its TTL is deleted by id. A loser deletes its own copy and refuses
   the operation, naming the winner's holder (email, hostname, acquired-at).
   A create refused as racing another write (409) is made once more by
   `op.rs`'s `ShellRunner`, as every `op` call is.
2. Perform the mutation through the command queue.
3. Flush the queue to 1Password.
4. Release — delete the held `CA_Lock` by its id.

The frontend wraps write calls in `withLock()` in
[api/tauri.ts](../frontend/src/api/tauri.ts) so the lock lifetime always
matches a single logical operation.

`store_ca_database()` first writes the local backup (when enabled; a failure
only logs a warning), then persists the SQLite dump to the canonical
`CA_Database` 1Password document. Documents are handed to `op` as a temp-file
path, never piped: piping without an explicit `-` made `op` keep only the first
64 KiB pipe buffer, silently truncating larger databases. The slower **private-store** copy (e.g. the `s3://`
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
  - `conn: Connection { vault, ca }` — the live 1Password vault and the loaded
    `CertificateAuthority`. A single mutex makes connect/disconnect atomic
    with respect to in-flight operations. `ensure_ca()` lazily retrieves the
    CA from 1Password on first use; it and `init_ca` work on a clone of `vault`
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
  - `database_error` — why the connected vault's `CA_Database` couldn't be
    loaded, shown by the recovery dialog. Cleared with the connection.
  - `conn.operator` — the ACME operator identity and when it was minted (see
    [ACME broker client](#acme-broker-client)). Dropped with the connection.
- [commands/](../crates/opca-tauri/src/commands) — one module per
  feature area (`aws`, `backup`, `broker`, `ca`, `cert`, `crl`, `csr`, `database`, `dkim`, `openvpn`,
  `subordinate`, `vault`, `lock`, `connect`, `dashboard`, `files`, `logs`, `update`). Each
  module exposes `#[tauri::command]` async functions that deserialise DTOs,
  call into `opca-core`, and return serialisable results. DTO shapes are
  defined in [commands/dto.rs](../crates/opca-tauri/src/commands/dto.rs).
  The certificate, CSR and CRL Inspect commands read their fields from
  `wslib_crypto_x509::inspect`, `CsrView` and `CrlView`: subject and issuer
  in RFC 4514 form (`EMAIL=…,O=…,CN=…`), the decimal serial, the key as
  opCA's `RSA` / `EC` / `Ed25519` with `KeyDescription::bits` (none for
  Ed25519) and OpenSSL's signature algorithm names. The raw dump beside them
  stays OpenSSL's `to_text()`.

The shell is intentionally thin: no PKI logic lives here, only glue between
the webview and `opca-core`.

### Holding a quit during 1Password work

`wslib-tauri`'s `quit_guard` plugin, given `AppState::is_busy` in `main.rs`,
keeps the app from exiting part-way through an `op` operation. `AppState::is_busy` is true while
the `conn` mutex (held by every `op` call) or `private_store_lock` is held. An
`ExitRequested` or window `CloseRequested` arriving then is prevented, the
frontend is sent `quit-pending` (shown as a notice), and a watcher exits once
the app is idle. macOS's predefined Quit terminates without an event that can
be held, so the app menu's Quit is replaced with a custom Cmd+Q item routed
through the same check. A forced quit or the Dock's Quit still bypass it.

### Database recovery

`detect_vault_state` parses the downloaded `CA_Database`; if it can't be
loaded the vault state is `database_unreadable` (alongside `valid_ca`,
`empty_vault`, `invalid_ca`), and `ensure_ca()` keeps the session connected.
The frontend opens `DatabaseRecoveryDialog`, which lists the vault's local
backups (age first, then exact local time; copies over 7 days old are flagged)
and, after a confirm step that spells out the age, calls `restore_local_backup`
under `withLock`. `CertificateAuthority::restore_from_backup` refuses a backup
from another vault ID or whose `CA` row serial doesn't match the vault's CA
certificate, saves the unreadable 1Password copy as `…-unreadable.sql` (never
listed or pruned), then stores the backup's dump as `CA_Database`. The CLI
reports the newest local backup and its age instead.

### Dev-only MCP server

The `mcp` cargo feature (on in `npm run tauri:dev`) compiles
[mcp/](../crates/opca-tauri/src/mcp) in, which serves an MCP endpoint on
`127.0.0.1:${OPCA_MCP_PORT:-8790}` behind a bearer token (`OPCA_MCP_TOKEN`, or
random), and writes `{url, token}` to `target/mcp.json` (0600). Combining
`mcp` with a release build is a `compile_error!`, so no shipped binary carries
it. The server comes from `wslib-mcp`, published to the private `wired-square`
cargo registry; cargo resolves it even with the feature off, so CI reads it
through the registry mirror (`.cargo/mirror.toml`).

- **Read tools** — `app_status` and `list_certs` read `AppState` and never call
  `op` (not even `ensure_ca`).
- **UI tools** — `navigate`, `set_theme`, `resize_window`. The app is changed
  only through the UI under test.
- **DOM tools** — `query`, `wait_for`, `console` (read-only), `click`, `type`,
  `press`, from `wslib-mcp`'s `dom` feature via `impl DomBridge for OpcaTools`.
  `query` reports every element matching a CSS selector (optionally filtered
  by visible text) with its form state, rect, whether it sits wholly in the
  viewport, and the overflow ancestor clipping it.

Everything except `resize_window` crosses `wslib-mcp`'s `tauri-bridge`: its
`TauriBridge` emits `harness:request {id, op, args}` to the main window and
awaits the matching `harness:reply`, timing out after 10 s. The webview side is
`@wired-square/mcp-bridge` (`/dom-ops`, imported first because it installs the
console capture, and `/tauri-bridge`);
[harness/start.ts](../frontend/src/harness/start.ts) starts it with the
`navigate` and `set_theme` app ops. All are imported only under
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
warning) and a mirrored CRL status (next_update, or a batch's signed-until,
+ graduated warning from `assess_crl_expiry`), along with a `pending_csrs` count,
the active broker count and the flagged `brokers_flagged` rows, and an
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

A single-page SolidJS app. Shared primitives come from `@wired-square/kit`,
read from the `mirror.wiredsquare.com/npm/` registry mirror:
`frontend/.npmrc` names the registry for the scope, and the token lives in the
user's `~/.npmrc` (CI writes it there from the same secret as the cargo
mirror). Its `theme.css` and `kit.css` load before opca's
stylesheets, and `kit.css` sits in a cascade layer, so opca's unlayered rules
win. Key conventions:

- [App.tsx](../frontend/src/App.tsx) routes based on `vaultState`
  (`valid_ca` / `empty_vault` / `invalid_ca`) returned by `connect`. Empty
  vaults are steered to CA initialisation; broken vaults to the dashboard
  with an error banner.
  It also wraps every page in the kit's `DateModes` (UTC first, `en-AU`,
  opca's countdown / time-ago wording for relative), which the
  `DateModeToggle` beside a date cycles. Stored ASN.1 dates are read by
  `asn1Date` in [utils/dates.ts](../frontend/src/utils/dates.ts) and shown by
  `StoredDate` (the kit's `When`); `useDateText` gives the same text for row
  search filters and string-valued detail rows.
- [pages/Connect.tsx](../frontend/src/pages/Connect.tsx) asks for the
  account first, then the vault, each with a Browse button. The account list
  is `list_accounts` — `op account list`, which reads local CLI config and so
  works signed out — loaded on mount alongside `check_op_cli`; a failure or an
  empty list disables the account Browse. The vault Browse is the only thing on
  the page that runs `list_vaults` (`op vault list`, which needs a sign-in),
  for the account in the field, kept per account value, so focusing or typing
  never lists and a failure retries on the next browse. Previously-used logins
  (localStorage, newest first) are in a "Recent logins" dropdown below the form
  that fills both fields without calling `op`. The account field
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
  the rejection to the kit's `Refusal`, carrying the backend's message so kit
  components show it as written, and tracks the in-flight operation — kept
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
  per-row `ActionMenu`; Ignore / Revoke / Send-to-Vault are self-contained
  dialogs on the kit's `Dialog` or `Confirm`, reused across those pages.
  Multi-select tables keep their selection in the kit's `createSelection`,
  cleared on a refetch, and tick rows with `TableTick`, the kit's `Tick`
  named for screen readers only.

### Styling tokens

The CSP forbids static inline styles, so all styling lives in
[styles/](../frontend/src/styles) and refers to tokens rather than
literals. Colours that differ by theme are defined in
[styles/theme.ts](../frontend/src/styles/theme.ts) (`darkTheme` /
`lightTheme`). Those the kit shares carry its names (`--app-bg`,
`--app-surface`, `--app-text`, `--app-text-muted`, `--app-accent`,
`--app-good` / `-warn` / `-bad` / `-neutral`, `--app-border`, …); opca's own
keep theirs (`--bg-elevated`, `--text-tertiary`, `--info`, `--caution`,
`--link`, …). The `theme` store hands both sets to the kit's `applyTheme` once,
as an adopted stylesheet, and switches between them with the kit's
`data-app-scheme` attribute, which also sets `color-scheme` so native controls
follow the app's theme. The kit's `SchemePicker` (header and Connect page)
offers system, light and dark; with no choice kept, the app follows the OS
appearance. The choice is kept under the kit's storage key; a value under the
old `opca-theme` key is carried over once. Everything that does not vary by theme is a static `:root` variable in
[styles/global.css](../frontend/src/styles/global.css): status tints and
edges derived with `color-mix` (`--{success,error,warning,caution,neutral,link}-{tint,edge}`),
the kit tokens opca derives from its own (`--app-surface-sunken`,
`--app-*-bg`, `--app-alert`, `--app-radius`, `--app-shadow`, `--app-focus`, …),
`--radius-*`, `--shadow-*`, `--overlay`, `--font-mono` and `--z-sticky`.
Dialogs, popovers and menus need no z-index: they sit in the platform's top
layer, each above the one opened before it. opca's CSS reset is in a `reset`
cascade layer ordered below the kit's, so the kit's components keep their
spacing. New styles use these tokens; a raw hex or pixel radius in a component
stylesheet is a regression.

### Popovers

Anything that floats over the page — the row and header action menus,
`VaultPicker`, `VpnClientPicker` and Connect's account and vault pickers —
is the kit's. [components/ActionMenu.tsx](../frontend/src/components/ActionMenu.tsx)
renders a `MenuAction[]` (built by `certKebabItems` for certificates) as the
kit's `Menu` / `MenuItem`: a ⋮ trigger, a `popover="auto"` panel the platform
light-dismisses, arrow keys over every item including disabled ones, Escape
and a chosen item handing focus back to the trigger. Pickers use the kit's
`Popover` and `PopoverOption`: mounted while open, on `popover="manual"`
pinned to an anchor (a press on the anchor counts as inside), focus left where
it was so a field keeps typing, and closed on an outside press, Escape, an
outside scroll or a resize. Both are top-layer, so one opened in a dialog is
drawn above it with no portal, and both prevent Escape's default so a
surrounding dialog stays open. [styles/components/popover.css](../frontend/src/styles/components/popover.css)
restyles the kit's `app-popover` / `app-menu` classes in opca's look; the
kit's `PopoverOption` takes no class, so a row's own layout class goes on an
element inside it.

### Copying

Every copy writes through `writeClipboard` in
[utils/clipboard.ts](../frontend/src/utils/clipboard.ts), the Tauri
clipboard plugin, because WKWebView refuses `navigator.clipboard` once an
`await` separates the write from the click. `CopyableValue` and the section
labels over text dumps, PEMs and DNS records are the kit's `CopyButton` with
that writer, flashing "Copied" in place of opca's glyph (given to the kit
through `IconSet` at the root) once the write lands. Availability tags and the
private-key copies, whose value is fetched on click or which are disabled,
busy or blocked in ways `CopyButton` does not draw, flash through the kit's
`createFlash`; `copyThenRecord` records the audit entry only after the write
succeeds and drops a refused write, as `CopyButton` does.

### Publishing to a store

Generating a CRL, re-signing the CA and mutating the database all leave the
copy in the store stale — the backend does not upload as a side effect. That
follow-up is one mechanism, not three:
[utils/publishFlow.ts](../frontend/src/utils/publishFlow.ts)'s
`createPublishFlow({ upload, success })` is the upload's own kit action plus
the offer-to-upload state; the page renders its outcome with `ActionOutcome`
beside its other actions', and the CA page reports a re-sign through it.
[components/UploadPrompt.tsx](../frontend/src/components/UploadPrompt.tsx)
renders the amber prompt from it.

### When a page throws

Resource getters rethrow on read, so a failed load would otherwise blank the
window. The kit's `ScreenBoundary` wraps the route outlet *inside* the layout
(`App.tsx`), so the sidebar and header stay usable and the user can navigate
away — which recovers on its own, because the router rebuilds the outlet, so
it takes no `pathname`. It shows the `Refusal`'s sentence, or the kit's generic
one for anything else, with "Try again" for retrying in place. This catches
render-time throws only; failures inside async event handlers, which is where
nearly every command lives, are reported by the page through its action.

### Confirming destructive actions

Anything irreversible goes through the kit's `Confirm`, never a bare button. It
sits on the kit's `Dialog`, a native modal `<dialog>` in the top layer that is
open while mounted, so each wrapper renders it inside a `<Show>` and every open
starts fresh. `Confirm` owns the pending and error state, holds Escape and
Cancel while the act runs, closes only on success, shows the act's `Refusal` in
the dialog, and takes a `children` slot plus a reactive `disabled` for callers
that need their own field. [utils/acting.ts](../frontend/src/utils/acting.ts)'s
`createActing()` adds opca's "Revoking…" verb while the act runs and keeps any
other failure's message as written. Bulk cert actions use `Confirm` with a
`reason` field when ignoring; `ResignCaDialog` adds a validity-days field;
`RevokeCertDialog`, `DeleteCertDialog` and `IgnoreCertDialog` wrap it with a `certLabel` message.
The wrappers only pass props, so `confirm.test` owns the shared behaviour and
each wrapper's test asserts just its wiring.

Re-signing the CA earns a confirmation despite keeping the key, subject and
serial (so issued certificates still chain): `re_sign_ca` overwrites the vault
item with `op item edit` and takes no snapshot, so **opCA cannot undo it** —
recovery means 1Password's own item history or a vault restore. It also does not
publish, so the CA page offers to upload afterwards, the same way the CRL page
does after Generate.

### Reporting the outcome of an action

The operation indicator above is strictly *in-flight* — it clears the moment a
command returns and carries no terminal state. Actions that change the vault
therefore report their own outcome through the kit's `createAction()`: one per
button so `pending()` gates just that button, or one shared across a group that
is enabled and disabled together (the certificate detail page's kebab). `run()`
never throws; its `then` calls `succeed(sentence)`, which clears itself after
four seconds, and a failure stays as `failed()` until the action next
succeeds. [utils/acting.ts](../frontend/src/utils/acting.ts)'s
`headed(headline, act)` turns the act's failure into a `Refusal` reading
`headline: reason`, so the sentence names the action that failed. The headline
is read after the act fails, so it can say how far a partial failure got —
"generated, but the upload failed".

[components/ResultBanner.tsx](../frontend/src/components/ResultBanner.tsx)
renders through the kit's `Notice`:

| Renderer | Used for |
| --- | --- |
| `ActionOutcome` | one action — a good notice for its success, a bad one for its failure |
| `ResultBanner` | bulk runs — a neutral `n succeeded` count plus per-item failures, dismissable |

A bulk count is reported neutrally rather than good: a partially-failed run
should not read as simply "good". A page whose actions each have their own
button (CRL's Generate and Upload, the certificate detail's kebab and VPN
regenerate) renders one `ActionOutcome` per action.

An error that belongs to the page rather than to one action is
`<Notice tone="bad">`, which renders nothing when empty; a resource's error
goes through `failureOf` (in `utils/acting.ts`), which is nothing until the
load fails and the refusal's sentence after. An error under a form (the CA
tabs, the create/import pages) adds the `form-notice` class for the form's
spacing.

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

- **Unit** — `cargo test -p opca-core`. Uses `wslib-1password`'s `FakeRunner`
  to script `op` output; an unscripted call fails. No network, no `op` binary.
- **Tauri commands** — `cargo test -p opca-tauri`. Under `cfg(test)`
  `state::Runner` is the `FakeRunner` (via core's `test-support` feature), each
  test scripting the calls it makes,
  and `test_harness::Harness` builds a `tauri::test::mock_builder` app over a
  loaded in-memory CA, invokes commands over IPC with the frontend's argument
  names, and exposes the recorded `op` calls, action log and emitted events.
- **Integration** — `OPCA_INTEGRATION_TEST=1 cargo test -p opca-core --test
  op_integration`. Exercises the 1Password client against a real `op`
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
- **ACME broker** — `cargo test -p opca-acme-broker` runs in-process over
  loopback against a fake step-ca (a shell script) and an in-memory opca-core
  CA (a dev-dependency, with `test-support`);
  [tests/opca_client.rs](../crates/opca-acme-broker/tests/opca_client.rs) runs
  opca-core's broker client against it. `sh
  crates/opca-acme-broker/tests/docker.sh` is the gated Docker check: see
  [Packaging and verification](#packaging-and-verification).
- **GUI flow** — with the dev app up and disconnected, `npm run harness:flow`
  starts a CA in a new `opca-flow-*` vault through the connect screen, then
  issues, revokes and deletes a certificate through the Certs page, asserting on
  the DOM and `list_certs`; teardown forgets the saved login and deletes that vault.

---

## ACME broker (`opca-acme-broker`)

A daemon for a Debian host on the LAN. It owns one name-constrained subordinate
CA's key, pairs with opCA once, serves the API opCA calls, and runs step-ca as
its child to answer ACME for appliances. The operator's guide is
[acme-broker.md](acme-broker.md).

Organised under [src/](../crates/opca-acme-broker/src):

- [config.rs](../crates/opca-acme-broker/src/config.rs) — `broker.toml`:
  `host` (required), `listen` (`[::]:9443`), `domains`, `state_dir`
  (`/var/lib/opca-acme`), `step_ca` (`/usr/bin/step-ca`), `acme_listen`
  (`[::]:443`). Unknown keys are refused.
- [broker.rs](../crates/opca-acme-broker/src/broker.rs) — `Broker::start`
  checks the host, the step-ca version and the state directory
  (`wslib_service::private_directory`), then loads or makes the subordinate key
  and CSR, the API identity (`wslib_tls::Serving::load_or_mint`) and the
  pairing code (`wslib_pairing::OneTimeCode`). `reload` re-reads all of it on
  SIGHUP. `locked` runs each change under the state lock in `spawn_blocking`,
  answering 500 after `LOCK_TIMEOUT` (5 s) while the work still finishes whole.
- [enrolment.rs](../crates/opca-acme-broker/src/enrolment.rs) — enrolling
  mode and the checks a chain and its `IssuanceConfig` must pass, shared with
  the chain push.
- [enrolled.rs](../crates/opca-acme-broker/src/enrolled.rs) — enrolled mode:
  the operator-only TLS config, status, fresh CSR, chain push, revoke, and the hooks
  into step-ca.
- [api.rs](../crates/opca-acme-broker/src/api.rs) — the axum routes, served by
  `wslib-http-server`.
- [step_ca.rs](../crates/opca-acme-broker/src/step_ca.rs) — step-ca's config,
  its version check and the child's supervisor.
- [cli.rs](../crates/opca-acme-broker/src/cli.rs) and
  [bin/opca-acme.rs](../crates/opca-acme-broker/src/bin/opca-acme.rs) — the
  `opca-acme` command line.

### How it meets opca-core

The broker doesn't link opca-core; opca-core's
[client](#acme-broker-client) calls it. opCA signs the broker's CSR with
`sign_subordinate` and later re-signs a fresh one with `renew_subordinate`
(see [Subordinate CAs](#subordinate-cas)); each subordinate is a row in the
`brokers` table. The broker checks what comes back on its own: the chain's
first certificate carries its key and the last is the self-signed root that
issued it, the `IssuanceConfig`'s domains equal the subordinate's DNS name
constraints (and the broker's `domains`, when set), and `host` is a DNS name
within them, since step-ca's own TLS certificate is issued for it. A chain push
must also keep the root. Bad input is a 400 that costs no pairing attempt.

### Two TLS modes

Both serve the broker's own self-signed API certificate; its SPKI SHA-256 is
the `pin` in the pairing URI (`opca-enrol://host:port#pin=…&code=…`), and it
survives re-enrolment.

- **Enrolling** — the `Serving` config with no client auth, and only
  `GET`/`POST /v1/enrolment`. The POST redeems the code (5 attempts) after
  every check passes. The record is staged before the redeem and promoted after
  it, so an accepted code can't meet a failed write.
- **Enrolled** — `wslib_tls::Serving::with_client_auth_pinned(root, pin)`:
  a client certificate must chain to the enrolled root *and* carry the
  operator's pinned key, since the root also issues VPN and device
  certificates. It consumes its `Serving`, so the broker loads a second one
  from the same files and refuses if that key differs from the served one.
  `Tls::reload` swaps it in on the open listener. Each enrolled route also
  checks the presented certificate (`PeerCertificates`), which turns away a
  connection opened before the swap. Routes: `GET /v1/status`, `POST /v1/csr`,
  `PUT /v1/chain`, `POST /v1/revoke`; the enrolment routes answer 404. A
  revoked broker answers only status and revoke.

### step-ca as a child

`Files::write` turns `enrolment.json` into `step-ca.json`, `step-ca-root.crt`
and `step-ca-intermediate.crt`: the unencrypted `subordinate.key` as the
intermediate's key (so no password), one ACME provisioner (`acme`, so the
directory is `/acme/acme/directory`) with the enrolled challenges and leaf
lifetimes, an x509 policy allowing each permitted domain and its subdomains,
and a badgerv2 database in `step-ca-db/`. `StepCa` starts the child on a new
chain or SIGHUPs a running one, restarts it 10 s after it dies, and SIGTERMs it
on revoke and reopen. On daemon stop it waits 5 s after the SIGTERM, then
SIGKILLs it. `step-ca version` must
report 0.28.1 or newer at start. The status's `state` is `issuing` while the
child lives, `step_ca_down` otherwise, and `revoked` once revoked.

### State directory

`/var/lib/opca-acme`, 0700, owned by `opca-acme`:

- `subordinate.key` (0600, unencrypted), `subordinate.csr`;
- `api.crt`, `api.key` — the API identity;
- `pairing-code` — the code's hash and attempts;
- `enrolment.json` — chain, operator pin, issuance config, the API pin opCA
  saw, and `revoked`;
- `step-ca.json`, `step-ca-root.crt`, `step-ca-intermediate.crt`,
  `step-ca-db/`;
- `archive/<time>/` — what each reopen set aside;
- `broker.pid`, `step-ca.pid`, `state.lock`, `pairing-code.lock`.

The file is the authority throughout: the daemon re-reads the code and the
enrolment from disk, so the command line can change them under `state.lock`.

### Command line and reload

`opca-acme pairing` issues a new code while enrolling; `status` reads the state
directory; `enrol --reopen` (root only) archives the enrolment and step-ca's
files, deletes the subordinate key, makes a new one and a new code, and
SIGHUPs the daemon through `broker.pid`. Run as root, the command line drops to
the state directory's owner with setgid/setuid first, so nothing it writes is
root's. The daemon's `reload` re-reads the subordinate and the mode, swaps the
TLS config back and stops step-ca.

### Packaging and verification

[debian/](../crates/opca-acme-broker/debian) holds the systemd unit
(`Type=notify`, `User=opca-acme`, `StateDirectory`, `ExecReload`,
`CAP_NET_BIND_SERVICE` for step-ca's 443, and hardening), the sysusers entry,
the commented `broker.toml` and a postinst note. `[package.metadata.deb]` in
the crate's `Cargo.toml` drives `cargo-deb`; the `acme-broker` job in
[build.yml](../.github/workflows/build.yml) builds `-p opca-acme-broker` alone
against the system libssl3 and attaches the `.deb` to `v*` releases.

[tests/docker.sh](../crates/opca-acme-broker/tests/docker.sh) builds the Linux
binaries and the `.deb` in a throwaway `rust:1.99-bookworm` container from a
vendored copy of the two crates, takes step-ca out of `smallstep/step-ca:0.28.1`,
and runs [tests/step_ca_docker.rs](../crates/opca-acme-broker/tests/step_ca_docker.rs)
with `OPCA_ACME_DOCKER_TEST=1`: step-ca issuing to lego over http-01 and
refusing an out-of-domain name, a renewal reloaded by SIGHUP, the command
line's privilege drop, and the `.deb` installed and enrolled under systemd in
`debian:bookworm`. Without the variable those tests skip.

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

The Lambda never talks to 1Password and holds no key. Its one write is
releasing a due batch CRL to the public `CRL_KEY`.

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
  `CRL_DAYS` is flagged as a warning (in batch mode, within 3 days or
  `CRL_DAYS` if lower).
- **CRL batch** — only while `config.crl_batch_enabled` is on in the dump:
  verifies every CRL in the batch against the CA certificate, publishes the one
  with the latest `thisUpdate` ≤ now if its CRL number is above the published
  one (never rolls back; one bad CRL refuses the batch), and warns when fewer
  than 2 are unreleased or the batch can't be read. Off, the batch is never
  fetched.
- **ACME brokers** — from the `brokers` table, for each active broker with a
  `url`: its subordinate (read from its certificate row) expiring within 30
  days, a `last_contact` older than 35 days, or none at all (signed, not
  delivered). These are the app's [concern](#acme-broker-client) thresholds.
  The Lambda can't reach brokers on the LAN, so the age of `last_contact` is
  its only sign that one is unreachable. Revoked brokers and subordinates
  signed by hand are skipped, and a dump from before the table (schema v17)
  has no section.

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
| `PENDING_CRL_KEY` | Batch object in the private bucket, including the store's prefix (default `pending-crl/crl-batch.pem`) |
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
