# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Start a new CA from the connect screen.** **New CA in a new vault…** creates the
  1Password vault, refusing a name that is already taken, then opens CA initialisation.
- **CA Days** on the CA initialisation form sets the CA certificate's own lifetime,
  separately from issued certificates. New CAs default to 10 years for the CA,
  365 days for certificates (was 3650, over Apple's 825-day limit for TLS server
  certificates) and 30 days for the CRL.
- **EC keys, by default.** New certificates and CSRs get an EC P-256 key and a new CA an
  EC P-384 key; RSA 2048 and 4096 stay available from the new **Key Type** field (and
  `--key` on `opca ca init`, `cert create` and `csr create`). Apple developer CSRs default
  to RSA 2048, the only kind Apple accepts.
- **Rekey to a different key type.** Rekeying, single or bulk, now confirms first and
  offers a Key Type, defaulting to keeping the current one, so an RSA certificate can move
  to EC in place (`opca cert rekey --key`).
- **IP address, email and URI SANs** alongside DNS names, in the app and via `--alt`. The
  SAN field says what it recognised as you type (DNS name, IPv4/IPv6 address, email, URI)
  or why an entry is invalid, and won't add an invalid one. A certificate whose Common Name
  is an IP address gets it as an IP SAN.
- **Delete CSRs** from the CSR list, or with `opca csr delete -n <cn>`. Deleting a pending
  CSR archives its 1Password item, private key included. Pending CSRs older than 30 days
  are marked **stale**.
- **Passphrase-encrypted key copy.** The private-key copy dialog can encrypt the key with a
  passphrase (typed or generated) before it reaches the clipboard, for certificates and
  DKIM keys alike.
- **Developers:** `npm run tauri:dev` starts a local MCP server for driving the app window by
  CSS selector, and `npm run harness:walk` uses it to check every popover's layout in both
  themes. It is compiled into development builds only. Building now needs SSH access to the
  private `lib-wiredai-rs`.

### Changed

- Creating a vault from the vault picker now also refuses a name that is already taken.
- **Web Server** is the default type on **Create Certificate**.
- Copying a certificate's private key is immediate: the key is kept from when the page
  loaded, in memory only, and dropped when you leave the page.
- EC leaf certificates no longer claim Key Encipherment, which ECDSA keys can't do.
- **Developers:** the Cargo workspace and frontend moved from `rust/` to the repository
  root, so build and `npm` commands run from there.

### Fixed

- Initialising a CA in the app always failed: opening the CA page on an empty vault
  dropped the connection ("Not connected"), and the form had no Common Name to send. It
  now has a required **Common Name** field.
- A new CA got a 2048-bit RSA key rather than the intended 4096; it now gets the chosen
  key type (EC P-384 unless set).
- Signing a CSR kept only its DNS SANs, silently dropping IP addresses. VPN client
  certificates now keep the SANs in their CSR.
- `opca cert create --serial` no longer fails trying to generate a zero-bit key.
- Row action (⋮) menus open upward when there is no room below, instead of running off
  the bottom of the window, and can be driven with the arrow keys.
- The vault picker in **Send to Vault** and **Add VPN Profile** is no longer cut off by the
  dialog, and closes when you click outside it.
- Opening a certificate no longer re-uploads the CA database every time when its stored
  bundle lacks some of the details the list is missing.

### Removed

- The deprecated Python implementation (`python/`). Its final source remains at commit
  `8a75b1f` (release 0.99.7) and on PyPI.

## [0.101.0] - 2026-08-02

### Added

- **Per-user AWS credentials.** The 1Password item holding your AWS access key
  is now chosen in **CA → Stores** and stored locally on your machine, keyed by
  1Password account. Operators who share a CA each select their own key, and
  those working across several tenants keep a separate selection per tenant.
  The CLI equivalent is `opca aws list|show|use|clear`.
- **AWS region** is now configurable per CA (`ca_aws_region`, schema v13),
  settable in **CA → Stores** or via `opca database config-set ca_aws_region`.
  It applies to both `s3://` stores and Route53. Previously the region was
  hard-coded to `ap-southeast-2`, which remains the fallback.
- **Re-signing the CA now asks for confirmation.** It previously took two
  ordinary clicks with no warning, while `re_sign_ca` overwrites the certificate
  in 1Password with no snapshot — opCA cannot undo it. The dialog says so
  plainly, and since re-signing does not publish, the CA page now offers to
  upload the new certificate afterwards, as the CRL page does after Generate.
- **Actions that change the vault now report a final status.** The sidebar
  indicator only shows work in flight, so these previously left no trace at all
  on success. A result banner — green and self-clearing, or red and persistent
  so the error stays readable — now covers CRL generate and upload, the
  Dashboard's regenerate/upload CRL, revoke, ignore and unignore (from both the
  certificate list and its detail page), DKIM key deletion, and the CA's Save
  Configuration and Save Stores, which changed nothing on screen at all.
- **The connect screen's Account field now has a picker**, listing the accounts
  configured in the local `op` CLI by email and sign-in address so the address
  need not be recalled and typed. Picking one fills in the sign-in address;
  where two accounts share an address — a personal and a work account both on
  `my.1password.com`, say — it fills in that account's UUID instead, since `op`
  cannot resolve the shared address on its own.

### Changed

- **CA → Certificate** puts Re-sign and Upload in the page header beside the
  title, matching the CRL page, and reports both through the same result banner
  instead of two inline messages.
- OPCA no longer reads `~/.config/op/plugins/aws.json`, so `op plugin init aws`
  is no longer a prerequisite. That file holds one machine-global default and
  OPCA always took its first entry, which failed outright when that entry
  belonged to a different 1Password account than the one OPCA was signed in to.
  Items created by the shell plugin still work — the field labels are the same.

### Removed

- The unused `aws-config` dependency, which was the only thing pulling
  `aws-sdk-sts`, `aws-sdk-sso` and `aws-sdk-ssooidc` into the build — the AWS
  CLI-style credential chain (shared-config profiles, SSO, assume-role). OPCA
  builds its SDK clients from explicit credentials, so none of it was reachable;
  dropping it makes an accidental fallback to `~/.aws` impossible.
- The last AWS CLI dependency. `notification/aws_lambda_test.py` no longer
  shells out to `op plugin run -- aws configure export-credentials`; it reads
  the credential selected in OPCA with `op item get`, matching the app. The
  deployed Lambda is unaffected — it uses its execution role. `op` is now the
  only external CLI the project requires.

### Fixed

- **The GUI and the CLI now agree on which AWS credential you have selected.**
  The selection is stored per 1Password account, but the account was identified
  by whichever string was passed to `op --account` — a shorthand, a sign-in
  address and a UUID all naming one account gave three separate entries, and the
  GUI and CLI do not pass the same one. So an item picked in **CA → Stores**
  could be invisible to `opca aws show`, and vice versa. Every form now resolves
  to one account, and existing entries merge the first time the settings file is
  read — no need to re-pick. `opca aws show` also names the account by email and
  sign-in address rather than echoing back whatever you typed.
- A page whose data fails to load no longer blanks the window. The failure is
  caught and shown in the content area with a **Try again**, leaving the sidebar
  and header usable so you can navigate elsewhere. Several pages — OpenVPN, the
  Database activity log, Log — rendered nothing at all on a failed load.
- Re-opening the **Revoke Certificate** dialog after a failed revoke no longer
  shows the previous error.
- The Dashboard's **Regenerate & Upload CRL** left a stale "CRL expired" row on
  screen when the generate succeeded but the upload failed, giving no hint that
  a new CRL had already been written to the vault. It now refreshes either way
  and says which half succeeded.
- The **Add VPN Profile** dialog reported its result twice, and the page's copy
  was hardcoded to "VPN profile generated" — wrong for several profiles at once,
  and wrong again when profiles were registered without being generated.
- Screen readers were not told about the Dashboard's action errors or the vault
  backup's partial-failure warning (the case where a generated password fails
  to store), as neither carried `role="alert"`.
- `op` calls returning more than about 64 KiB (e.g. `op item list` on a large
  account) deadlocked and failed with a 30-second timeout. The runner polled
  for exit without draining the child's stdout, so the pipe buffer filled and
  `op` blocked writing; both pipes are now drained concurrently.

## [0.100.0] - 2026-06-10

### Added

- **Send to Vault** is unified across every entry point — the per-row **⋮** menu,
  the **multi-select** bulk-action bar, the single-generate result, and the
  bulk-generate result — into one shared block that **remembers the destination
  vault** for the session. Sending one or many profiles copies them all to one
  vault and reports any per-profile failures inline (the dialog stays open on a
  partial failure so the list is visible).
- **OpenVPN → Profiles** now shows an **Expiring Soon** status (orange) for a
  profile whose pinned cert is still valid but within 30 days of expiry —
  previously such a profile showed a green **Current** badge with no warning.
  This holds even when the cert has been **ignored** (ignore suppresses the
  alert, not the displayed status), matching the certificate list.

- **Bulk certificate operations.** The **Certificates → Local** list now has
  multi-select checkboxes (plus a select-all-visible header) and a bulk action
  bar to **Rekey / Renew / Revoke / Ignore** many certificates in a single
  vault-lock cycle. Buttons are gated to the selection (Renew/Revoke only when
  every selected cert is valid; Ignore only for expired/expiring, not-ignored
  certs), and the run reports a per-certificate success/failure summary. The
  status indicator shows live per-item progress (e.g. "Rekeying 3/7…").
- **OpenVPN profile lifecycle status.** The **OpenVPN → Profiles** list now
  shows a derived **Status** column — **Current**, **Needs Regen** (with the
  replacement cert serial), **Revoked**, or **Expired** — computed by comparing
  each profile's pinned cert serial against the live CA database. So after a
  bulk rekey/renew, the affected profiles flag themselves for regeneration, a
  revoked or expired cert's profile is obvious, and you can **multi-select and
  bulk Regenerate** (against the CN's current valid cert). A **Delete** action
  (kebab + bulk) removes a profile from the list (the `.ovpn` document stays in
  the vault). The Created column is now date-only.
- **Add VPN Profile** now takes **multiple certificates at once** — the picker is
  a searchable multi-select that only offers the current cert per CN (replaced
  and already-profiled CNs are filtered out), and one profile is recorded per
  selected cert (with a per-cert summary). The picker dropdown is portalled so a
  long fleet is no longer clipped by the dialog. A **Generate Profile** tickbox
  (on by default) controls whether the `.ovpn` document is produced now or the
  entry is just registered for later generation (it shows as Needs Regen until
  generated). The action button is now **Add**.
- The **OpenVPN → Profiles** table is **sortable** — click any column header to
  sort (Serial and Created default to newest-first), defaulting to CN ascending.
- The **Certificates → Local** list now has a per-row **⋮ actions menu** with
  Rekey, Renew, Revoke and Ignore/Unignore, so certificates can be actioned
  without opening them first. The menu's items mirror each cert's state (Renew
  and Revoke only on valid certs; Ignore only on expired/expiring certs that
  aren't already ignored or superseded; Unignore on ignored certs).
- **Ignore** now opens a unified dialog that **requires a reason**, used
  identically from the list and the certificate detail page; **Revoke** uses a
  shared styled confirmation dialog in both places.
- A kebab action on a legacy certificate whose **TYPE** shows "—" now
  opportunistically backfills its type from 1Password while it's already being
  touched, so the column fills in (rekey/renew enrich the source cert before
  acting; revoke/ignore/unignore enrich and refresh the list afterwards).
- The **OpenVPN → Profiles** list now has a per-row **⋮ actions menu** with
  **Send to Vault** and **Regenerate**, replacing the select-row-then-send panel
  below the table. Send to Vault opens a dialog that **remembers the destination
  vault** for the session once a send succeeds (with a **Remove** to clear it);
  Regenerate re-creates the `.ovpn` from the row's CN/serial/template.
- The certificate **detail** page now puts **Stored Items** at the top and makes
  the Serial, Common Name, Title, Subject, Issuer and SAN fields
  **click-to-copy** (each SAN copies individually, with a **Copy all** for the
  whole list). Its Rekey/Renew/Revoke/Ignore actions now live in a **⋮ menu**
  next to "Back to list" rather than a row of buttons at the bottom.
- After a **renew** or **rekey**, opCA now navigates straight to the newly
  issued certificate's detail page (it lives at a new serial) with a "New
  certificate" banner linking back to the predecessor. The new cert's
  certificate and private key are surfaced there via the existing copy-on-click
  indicators — the banner makes clear whether the private key is new (rekey) or
  unchanged (renew).
- When the renewed/rekeyed cert is a **VPN client** cert, the detail page offers
  a one-click **Regenerate VPN profile** using the template previously recorded
  for that CN (read from the local `openvpn_profile` table — no 1Password
  round-trip). If the CN has no recorded profile, it links to the OpenVPN page
  instead — and that link now opens the OpenVPN **Add-profile modal** with the
  cert **pre-selected by serial**, ready to generate.
- The OpenVPN **Add-profile** modal's certificate picker lists each valid VPN
  client *and server* certificate with a **coloured serial badge** (green =
  valid, orange = expiring soon) and its expiry date, so renewal duplicates —
  two valid certs sharing a CN — can be told apart and the current one
  identified. The profile's Client/Server type is inferred from the chosen cert.
- The OpenVPN page is now **Profiles-first**: the Profiles view is the landing
  tab, with **All / Client / Server** filter chips and a **+ Add** button that
  opens a modal to generate a profile (pick a cert, pick a template — the
  template defaults to the one last used for that CN). Server configuration (DH
  parameters, TLS-auth key) and template editing move to a separate
  **Configuration** tab.

### Changed

- Renewing or rekeying a certificate now **auto-ignores its predecessor**
  (`ignored_reason` = `renewed`/`rekeyed`, note `replaced by <new_serial>`),
  flushed by the existing database save — no extra 1Password calls. The
  predecessor shows the usual "Ignored" banner and can be un-ignored.
- **Ignoring a certificate is now purely a "don't notify about problems" flag**
  — it no longer changes the cert's status or classification. An ignored cert
  keeps its true status everywhere: the list shows `Valid`/`Expiring Soon`/
  `Expired` with an `ignored` chip, and `valid_certs` counts valid-but-ignored
  certs. Only the *alert* consumers subtract ignored certs — the dashboard's
  expiring/expired counts (and the expired action item), and the notification
  Lambda (`notification/aws_lambda.py`, via `AND ignored_at IS NULL`). Valid and
  revoked counts stay real. The cert detail page's **Ignore** action is now
  offered for **expiring-soon** certs as well as expired ones, so you can
  silence an acknowledged upcoming expiry.
- Certificates page: the default filter is now **Valid**; certificates inside
  the expiry-warning window show an orange **Expiring Soon** badge (including
  ignored ones); and the **Valid** filter lists every cert that passes
  validation — fully-valid, expiring-soon, and valid-but-ignored alike.
- The dashboard **Valid** count is now the real number of certs that pass
  validation (`certs_valid + certs_expires_warning`) — expiring-window certs are
  still valid, so they're counted as valid (and also surfaced in the Expiring
  Soon count).
- Dashboard count tiles (Total / Valid / Expiring Soon / Expired / Revoked) are
  now clickable and open the Certificates page pre-filtered to that status (and
  briefly flash when pressed). The certs page gains a matching **Expiring Soon**
  filter.
- VPN profiles are now stored as **`VPN_{serial}_{cn}`** (was `VPN_{cn}`),
  mirroring the cert's own `CRT_{serial}_{cn}` item: a renewed cert (new serial)
  gets a distinct profile rather than clobbering the previous one, while
  regenerating the *same* cert overwrites its document and upserts the
  `openvpn_profile` row.
- The OpenVPN **Profiles** tab now lists from the local database (no 1Password
  round-trip) with **Type** (Client/Server), **CN**, **Serial**, **Template**,
  and **Created** columns. The type is derived from the cert each profile was
  generated from.
- OpenVPN **templates** are now served from the local database (mirrored from the
  `OpenVPN` 1Password item) instead of a lazy `op` fetch, so the template
  dropdown is populated immediately — fixing the empty dropdown when arriving via
  the cert detail page's deep-link. The mirror seeds itself on first use (reading
  every template from a single item fetch rather than one `op` call per template)
  and the Configuration tab gains a **Refresh** that re-syncs from 1Password.
- The post-renew **"New certificate"** and **"VPN profile"** banners on the cert
  detail page are now pinned so they stay visible while scrolling the
  certificate/key content.
- The `renew_cert`/`rekey_cert` Tauri commands now return `{ serial, pem }` for
  the new certificate (previously just the PEM). New `get_vpn_profile_for_cn`
  command looks up a CN's recorded VPN profile from the database.

### Changed

- **Opening a just-renewed/rekeyed certificate no longer re-reads it from
  1Password.** The detail page's "Fetching details from vault…" step exists to
  pull the certificate PEM (not kept in the local DB); for a freshly-issued cert
  we now reuse the PEM captured during the renew/rekey, so the detail page shows
  it immediately instead of spending an `op` round-trip re-downloading what we
  just created. (Certs with an intermediate chain still fetch, to retrieve the
  chain PEM.)
- **The private-store (S3) database backup now uploads off the connection
  lock.** `store_ca_database` persists only the canonical 1Password document
  synchronously; the slower private-store copy (AWS creds fetch + PUT) runs in a
  background task that holds a dedicated lock rather than the shared connection
  mutex, so it no longer blocks reads (the cert/profile lists) or delays the
  screen refresh after an action. It's triggered once per mutation and skipped
  when the database is unchanged.

### Fixed

- **The side-nav activity status no longer blanks mid-operation.** A finishing
  background task (e.g. the database save after a backfill) emitted an
  "idle" status that cleared whatever foreground op was running — so a rekey
  showed "Acquiring lock…" → *nothing* → "Rekeying certificate…". In-flight
  operations are now tracked as a stack: the most recent is shown, a finishing
  background task only removes its own entry, and the indicator blanks only when
  nothing is actually running.
- **Mutating operations no longer upload the CA database to the private store
  twice.** `store_ca_database` already syncs the private store (S3) as part of
  every persist, yet the frontend also fired a second `upload_ca_database` after
  create/import/rekey/renew/revoke. Each upload holds the connection lock, so
  the duplicate doubled the post-action stall (and blocked the OpenVPN Profiles
  list behind it). The redundant frontend upload is removed; manual sync from
  the Database page is unchanged.
- **The OpenVPN Profiles list now fills the available height.** A leftover
  `max-height` (from when a send panel sat below the table) capped it at ~280px,
  leaving the lower half of the screen empty; the table now grows and scrolls
  like the other lists.
- **The Certificates header no longer shifts when switching tabs.** Moving to
  the Inspect tab previously hid the whole action bar, collapsing the header to
  the title height and nudging the tabs/table up; the Import button now stays
  visible on every tab so the header keeps a constant height.
- **Mutation actions (rekey, renew, revoke, …) now show "Acquiring lock…" and
  "Releasing lock…" statuses.** Acquiring and releasing the vault lock each
  write to 1Password (a few seconds) and previously ran with no indicator, so
  the spinner only appeared once the operation itself started and an
  unexplained pause followed it. Both lock steps now drive the side-nav status,
  bracketing the operation's own label.
- **The OpenVPN Profiles list showed a "Loading profiles…" delay** even though
  profiles come straight from the in-memory database. The Configuration tab's
  server-parameters resource (which reads from 1Password) was fetched eagerly on
  mount and, sharing the single connection lock, stalled the DB-only Profiles
  query behind it. That resource is now loaded lazily — only when the
  Configuration tab is opened — so the Profiles list renders immediately.
- **The Certificates status filter now sticks for the session.** Changing it
  (e.g. to "Expiring Soon") and navigating away then back to the Certificates
  page keeps the selection rather than resetting to "Valid". An explicit
  `?filter=` deep-link (e.g. from the Dashboard) still takes precedence.
- **Generated VPN profiles disappeared on restart.** The profile record was
  added to the in-memory database but never persisted, so it was lost when the
  CA database was reloaded from 1Password on the next launch (only the `.ovpn`
  document survived). Generating a profile now calls `store_ca_database()` after
  recording the row — mirroring the DKIM commands — so the Profiles list is
  retained across restarts.
- **VPN profile generation used the wrong certificate when two valid certs
  shared a CN** (e.g. after renewing a VPN client before the old cert expired):
  the template's `op://.../$OPCA_USER/...` references resolved `OPCA_USER` to the
  bare CN, which 1Password matched to the older, legacy-named item. Generation
  now selects the chosen cert by **serial** and points `OPCA_USER` at that cert's
  exact stored item title, so the profile always carries the selected cert's
  key/certificate. The picker disambiguates duplicates and the chosen serial is
  recorded on the profile (schema **v11** adds `openvpn_profile.serial`).

- **Compatibility with 1Password CLI 2.34.0**: `op read` no longer accepts
  `[type]` field-type qualifiers (e.g. `[text]`) inside `op://` secret
  references, which had broken the OpenVPN params page (DH and TA key-size
  lookups failed with `invalid character in secret reference: '['`).
  `Op::mk_url` now strips the qualifier transparently — the SET syntax used
  by `op item create/edit` is unaffected.
- **Private-key copy reliability in the desktop app**: the Copy buttons on
  the Certificate, External Certificate, and DKIM Key detail pages now go
  through Tauri's clipboard-manager plugin, so the copy still succeeds after
  the native confirmation dialog (previously failed with `NotAllowedError`
  in the Tauri webview because the user-activation gesture was consumed by
  the dialog). All other in-app clipboard copies migrate to the same plugin
  for consistency.

## [0.99.15] - 2026-05-07

### Added

- CSR list detail view: when viewing a Pending CSR, an **Import Signed Cert** action accepts the externally-signed certificate plus an optional upstream CA chain. The CSR's stored private key is paired with the new certificate and the result becomes an external certificate.
- External certificates tab: per-row **Generate CSR** action produces a fresh CSR (new key, same subject and SANs) from an existing external certificate, ready to send to an external CA for re-signing.
- New **Inspect** tab on the CSR page: paste any CSR PEM to see structured fields (subject, key type/size, SANs, signature algorithm, public-key SHA-256 fingerprint) plus the full `openssl req -text -noout` style dump.
- External certificates now have a detail view (mirrors the local cert detail page): subject, issuer, validity, key info, SANs, certificate PEM with copy. Click any row in the External tab.
- **Stored Items** row on certificate detail pages indicates whether the Certificate, Private Key, and Chain are stored alongside the cert. The indicators double as copy buttons — green with a copy icon when present, struck-through grey when absent, italic grey while the bundle is loading. Database-backed (schema v9 migration adds `has_private_key` and `has_chain` to the certificate tables) so availability is shown immediately on subsequent loads; legacy rows backfill lazily on first detail-page open.
- **Copy Private Key** lands on the clipboard without ever rendering on screen. A native Tauri confirmation dialog (with a heavy security warning) gates every copy. The backend refuses to export keys belonging to CA certificates outright — both via the `cert_type` column and by checking the X.509 BasicConstraints of the retrieved bundle. The corresponding indicator on a CA cert renders with a padlock and is non-interactive while keeping the green "stored" colour.
- **Copy Chain** action on certificate detail pages — copies the issuer chain PEM via the same indicator pattern.
- CRL page now has **Detail** and **Inspect** tabs. Detail loads the local SQLite metadata immediately and lazily fetches the CRL document from 1Password to populate the Stored Items indicator. Inspect prefills the live CRL PEM but accepts any pasted CRL — decodes into structured fields (issuer, last/next update, CRL number, signature algorithm, revoked count) plus the full `openssl crl -text -noout` style dump.
- Server-side audit logging for every clipboard copy of a certificate, private key, chain, CRL document, or CA certificate — entries appear in the Log page alongside the existing CA operations.
- CA Certificate tab now has the same **Stored Items** row as the cert detail pages: Certificate (green, copyable via the indicator) and Private Key (green, padlock — never copyable).
- New **Inspect** tab on the Certificates page: paste any certificate PEM to see structured fields (subject, issuer, serial, validity, key info, signature algorithm, SANs, public-key SHA-256 fingerprint, CA flag) plus the full `openssl x509 -text -noout` style dump.
- DKIM keys page now follows the same shape as the certificate detail pages. Clicking a row navigates to a per-key detail view at `/dkim/<domain>/<selector>`. Verify DNS, Deploy to Route53, and Delete actions live on the detail page; the keys list is just a clickable table.
- DKIM keys are now mirrored in a `dkim_key` SQLite table (schema v10) so the keys list renders without a vault round-trip. The first list call after upgrade syncs from 1Password; subsequent calls are local. The Refresh button re-syncs.
- DKIM detail page exposes a **Stored Items** row with Selector, Public Key, Private Key, and DNS Record indicators — green/copyable when present, padlock-blocked otherwise. Selector copies as `<selector>._domainkey` (the DNS host record name). Private-key copy goes through the Tauri confirm dialog and the same audit-logged backend path as cert keys.
- DKIM detail page shows a **Key Pair** match status (Matched / Mismatch / —) so out-of-band tampering with the stored public key is visible.

### Compatibility

- The DKIM `dkim_key` table (schema v10) is populated by the new client. If a vault is touched by a mix of old (≤ 0.99.14) and new clients during rollout, an older client may create or delete a DKIM key without updating the table. The keys list on the new client reconciles fully with 1Password on Refresh — additions are picked up and stale rows for deleted items are removed. No manual intervention is required beyond clicking Refresh once after a mixed-client period.

### Changed

- `CRL` detail now uses a fast/slow split: the local SQLite metadata renders immediately, and the actual CRL document loads from 1Password in the background. The previous combined fetch held the page hostage to the vault round-trip.
- The CSR / CRL / Certificate Inspect commands share a single `inspect_helpers` module — RDN-string formatting, public-key summaries, and signature-algorithm extraction are no longer duplicated across the three handlers.

### Fixed

- Inspect-tab placeholder on the Certificates page rendered the literal text `…` instead of an ellipsis character — JSX bare-string attributes don't process JS escapes.

## [0.99.14] - 2026-04-20

### Added

- Log viewer page: view, scroll, and copy application log contents directly from the UI
- SFTP storage backend (`sftp://[user@]host[:port]/path`) as a cross-platform alternative to rsync; `scp://` is accepted as an alias
- Consistent logging across all storage backends (rsync, S3, SFTP)
- System-level logging for all Tauri command entry points (mutating operations at info, locks at info, external calls at debug) with `[tauri]` prefix
- Dashboard CA and CRL status bubbles now show expiry and graduated warnings (critical / prominent / expired), with a timezone toggle anchored in the top-right of each bubble
- Dashboard action-items panel surfaces one-click fixes: regenerate (and optionally upload) the CRL when it nears expiry, jump to expired certificates, and review pending CSRs
- Pending CSRs bubble replaces the Vault bubble on the dashboard
- DKIM info and create views can toggle the DNS record between single-string and Route53-style 255-byte quoted chunks; Copy copies the visible form
- Expired certificates with a same-CN replacement (newer Valid cert, e.g. after renew or rekey) are now automatically marked as Superseded and drop out of the dashboard's expired-cert count. The cert detail page links to the replacement
- Certificates can also be manually ignored from the cert detail page for cases where there's no replacement (retired services etc.); each ignore records who set it, when, and an optional note
- Cert list filter gains "Superseded" and "Ignored" options; the Expired/Valid/Revoked filters now hide both ignored and superseded rows

### Fixed

- Fixed duplicate log output caused by appending to default log targets instead of replacing them
- Log directory now uses Tauri's platform-appropriate `LogDir` target instead of a hardcoded macOS path
- Dashboard refresh now rescans for passage-of-time certificate expirations and persists the updated statuses to 1Password immediately, instead of waiting for an unrelated write operation
- DKIM DNS verification no longer appends the system resolver's search domain to the query name; DKIM names are now looked up as absolute FQDNs

### Changed

- DKIM Route53 deployment now uses the native AWS SDK instead of shelling out to `aws` CLI via `op plugin run`
- S3 storage backend now uses `aws-sdk-s3` instead of `rust-s3`, unifying all AWS access on a single SDK

## [0.99.13] - 2026-04-01

### Added

- Frontend test infrastructure with Vitest, SolidJS testing library, and Tauri API mocks

### Fixed

- `vault_item_count` now propagates JSON parse errors instead of silently returning zero
- `read_lock` in vault lock now propagates real errors (auth, network) instead of swallowing them
- Fix timer leaks in frontend components: clipboard "Copied" feedback and navigation timeouts now clean up on unmount
- Replace `setTimeout(0)` focus hack in VaultPicker with `autofocus` attribute

### Changed

- Replace `innerHTML` SVG icon strings with a JSX `Icon` component, eliminating XSS-prone pattern
- Replace bare mutex `.unwrap()` with `.expect()` diagnostic messages across all Tauri command handlers
- Remove unused `CONFIG_ATTRS` constant from database module
- Enable Content Security Policy for the Tauri webview, restricting resource loading to self-origin and Google Fonts
- Extract all runtime `<style>` blocks from 20 components into dedicated CSS files, removing `unsafe-inline` from CSP
- Consolidate shared CSS patterns (detail grids, forms, status badges, data tables) into global.css
- Deduplicate per-page table classes into shared `data-table` classes
- Replace inline style attributes with CSS utility classes
- Replace `any` types with `Resource<DatabaseInfo>` in Database page components
- Improve accessibility: focus indicators on all interactive elements, aria-labels on icon-only buttons, `role="alert"` on error messages, modal dialog semantics, and operation status live region
- Self-host all fonts (DM Sans, JetBrains Mono, Ubuntu) via @fontsource, removing Google Fonts CDN dependency
- Tighten CSP to `'self'` only with no external domain allowances

## [0.99.12] - 2026-04-01

### Changed

- Bump GitHub Actions (`setup-node`, `upload-artifact`) from v5 to v6 for Node.js 24 compatibility

## [0.99.11] - 2026-04-01

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
