import { Show, For, createSignal, createResource } from "solid-js";
import { useNavigate, useSearchParams } from "@solidjs/router";
import {
  listCerts, listExternalCerts, inspectCertificate, unignoreCert, backfillCert,
  bulkRekeyCerts, bulkRenewCerts, bulkRevokeCerts, bulkIgnoreCerts,
} from "../api/certs";
import { certKebabItems, certLabel, rekeyAndGo, renewAndGo } from "../api/certActions";
import { generateCsrFromCert } from "../api/csr";
import { formatDate } from "../utils/dates";
import { createCopiedSignal, writeClipboard } from "../utils/clipboard";
import TzToggle from "../components/TzToggle";
import Spinner from "../components/Spinner";
import SearchInput from "../components/SearchInput";
import CertStatusBadge from "../components/CertStatusBadge";
import KebabMenu, { type KebabItem } from "../components/KebabMenu";
import IgnoreCertDialog from "../components/IgnoreCertDialog";
import RevokeCertDialog from "../components/RevokeCertDialog";
import BulkConfirmDialog from "../components/BulkConfirmDialog";
import ResultBanner, { ActionResultBanner } from "../components/ResultBanner";
import SelectAllCheckbox from "../components/SelectAllCheckbox";
import { createSelection } from "../utils/selection";
import { createActionResult } from "../utils/actionResult";
import type { BulkCertResult, CertListItem, ExternalCertListItem, InspectCertificateResult } from "../api/types";
import "../styles/pages/certs.css";

type BulkAction = "rekey" | "renew" | "revoke" | "ignore";

type Tab = "local" | "external" | "inspect";

const VALID_FILTERS = new Set([
  "all",
  "valid",
  "expiring",
  "expired",
  "revoked",
  "ignored",
  "superseded",
]);

// The chosen status filter, remembered for the session (module scope outlives
// the page component) so returning to Certificates keeps the selection. An
// explicit ?filter= in the URL still wins.
let sessionFilter = "valid";

export default function Certs() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const initialFilter = typeof searchParams.filter === "string" && VALID_FILTERS.has(searchParams.filter)
    ? searchParams.filter
    : sessionFilter;
  sessionFilter = initialFilter;
  const initialTab: Tab =
    searchParams.tab === "external" ? "external"
    : searchParams.tab === "inspect" ? "inspect"
    : "local";
  const [tab, setTab] = createSignal<Tab>(initialTab);
  const [filter, setFilter] = createSignal(initialFilter);
  const [search, setSearch] = createSignal("");

  const [localCerts, { refetch: refetchLocal }] = createResource<CertListItem[]>(listCerts);
  const [externalCerts, { refetch: refetchExternal }] = createResource<ExternalCertListItem[]>(listExternalCerts);

  const certs = () => (tab() === "local" ? localCerts : externalCerts);
  const loading = () => certs().loading;

  const filteredLocal = () => {
    let items = localCerts() ?? [];
    const f = filter();
    if (f === "ignored") {
      items = items.filter((c) => !!c.ignored_at);
    } else if (f === "superseded") {
      items = items.filter((c) => !!c.superseded_by);
    } else if (f === "valid") {
      // A still-Valid cert that's been ignored stays on the Valid view (it
      // renders with an "ignored" chip). Superseded rows are Expired, so they
      // never match the Valid status anyway.
      items = items.filter((c) => c.status?.toLowerCase() === "valid");
    } else if (f === "expiring") {
      // Certs inside the expiry-warning window. Ignored ones are excluded so
      // this matches the dashboard's "Expiring Soon" count (which subtracts the
      // acknowledged certs).
      items = items.filter((c) => c.expiring_soon && !c.ignored_at);
    } else if (f === "expired" || f === "revoked") {
      // Hide ignored/superseded audit-only rows so these views match the
      // dashboard's expired/revoked counts.
      items = items.filter(
        (c) =>
          c.status?.toLowerCase() === f && !c.ignored_at && !c.superseded_by,
      );
    }
    const q = search().toLowerCase();
    if (q) items = items.filter((c) =>
      [c.serial, c.cn, c.cert_type, c.status, c.expiry_date ? formatDate(c.expiry_date) : null]
        .some((v) => v?.toLowerCase().includes(q))
    );
    return items;
  };

  const filteredExternal = () => {
    let items = externalCerts() ?? [];
    const f = filter();
    if (f !== "all") items = items.filter((c) => c.status?.toLowerCase() === f);
    const q = search().toLowerCase();
    if (q) items = items.filter((c) =>
      [c.serial, c.cn, c.issuer, c.status, c.expiry_date ? formatDate(c.expiry_date) : null, c.import_date ? formatDate(c.import_date) : null]
        .some((v) => v?.toLowerCase().includes(q))
    );
    return items;
  };

  const statusBadgeClass = (status: string | null) =>
    `status-badge status-${(status ?? "").toLowerCase()}`;

  function handleRefresh() {
    if (tab() === "local") refetchLocal();
    else refetchExternal();
  }

  const [generatingSerial, setGeneratingSerial] = createSignal<string | null>(null);
  const [generateError, setGenerateError] = createSignal<string | null>(null);

  // Per-row certificate actions (kebab menu). Rekey/Renew navigate away to the
  // new cert; Revoke/Ignore use shared dialogs; Unignore acts immediately.
  const outcome = createActionResult();
  const [ignoreTarget, setIgnoreTarget] = createSignal<CertListItem | null>(null);
  const [revokeTarget, setRevokeTarget] = createSignal<CertListItem | null>(null);

  // --- Bulk multi-select (Local tab) ---------------------------------------
  // Selection is keyed by serial and auto-clears on every list reload (old
  // serials vanish after rekey/renew).
  const sel = createSelection(filteredLocal, (c) => c.serial, localCerts);
  const [bulkAction, setBulkAction] = createSignal<BulkAction | null>(null);
  const [bulkResults, setBulkResults] = createSignal<BulkCertResult[] | null>(null);

  const selectedSerials = () =>
    sel.selectedItems().map((c) => c.serial).filter((s): s is string => !!s);

  // Gating mirrors the single-row kebab rules (certKebabItems).
  const canRekey = () => sel.selectedItems().length > 0;
  const canRenewOrRevoke = () =>
    sel.selectedItems().length > 0 &&
    sel.selectedItems().every((c) => c.status?.toLowerCase() === "valid");
  const canIgnore = () =>
    sel.selectedItems().length > 0 &&
    sel.selectedItems().every(
      (c) =>
        (c.status?.toLowerCase() === "expired" || c.expiring_soon) &&
        !c.ignored_at && !c.superseded_by,
    );

  async function runBulk(reason: string) {
    const serials = selectedSerials();
    if (serials.length === 0) return;
    let results: BulkCertResult[];
    switch (bulkAction()) {
      case "rekey": results = await bulkRekeyCerts(serials); break;
      case "renew": results = await bulkRenewCerts(serials); break;
      case "revoke": results = await bulkRevokeCerts(serials); break;
      case "ignore": results = await bulkIgnoreCerts(serials, reason); break;
      default: return;
    }
    setBulkResults(results);
    sel.clear();
    refetchLocal();
  }

  // Per-action copy for the shared confirm dialog.
  const bulkDialogConfig = () => {
    const n = selectedSerials().length;
    switch (bulkAction()) {
      case "rekey": return { title: "Rekey Certificates", message: `Rekey ${n} certificate(s)? Each gets a fresh key and a new serial.`, confirmLabel: "Rekey", actingLabel: "Rekeying…", danger: false, requireReason: false };
      case "renew": return { title: "Renew Certificates", message: `Renew ${n} certificate(s)? Each is reissued at a new serial.`, confirmLabel: "Renew", actingLabel: "Renewing…", danger: false, requireReason: false };
      case "revoke": return { title: "Revoke Certificates", message: `Revoke ${n} certificate(s)? This cannot be undone.`, confirmLabel: "Revoke", actingLabel: "Revoking…", danger: true, requireReason: false };
      case "ignore": return { title: "Ignore Certificates", message: `Stop counting ${n} certificate(s) toward expiry alerts. Provide a reason for the audit trail.`, confirmLabel: "Confirm Ignore", actingLabel: "Ignoring…", danger: false, requireReason: true };
      default: return { title: "", message: "", confirmLabel: "", actingLabel: "", danger: false, requireReason: false };
    }
  };

  /** Messages for a per-row action. `ok` is omitted for rekey/renew, which
   * navigate away to a page that reports the outcome via its fresh-banner. */
  interface RowMessages { fail: string; ok?: string }

  // Run a per-row action, reporting the outcome in the list-level banner.
  async function run(msg: RowMessages, fn: () => Promise<unknown>) {
    outcome.clear();
    try {
      await fn();
      if (msg.ok) outcome.report(msg.ok);
    } catch (e) {
      outcome.report(msg.fail, e);
    }
  }

  // Enrich a legacy cert whose type is still "—" via the existing backfill
  // (one op read, persists in the background). Returns true if it ran.
  async function backfillTypeIfMissing(cert: CertListItem): Promise<boolean> {
    if (cert.cert_type || !cert.serial) return false;
    await backfillCert(cert.serial).catch(() => {});
    return true;
  }

  // Tail for list-resident actions (revoke/ignore/unignore): show the result
  // immediately, then enrich a missing type and refresh again.
  async function finishListAction(cert: CertListItem) {
    refetchLocal();
    if (await backfillTypeIfMissing(cert)) refetchLocal();
  }

  function certMenuItems(cert: CertListItem): KebabItem[] {
    const serial = cert.serial;
    const label = certLabel(cert);
    // Wrap a row action: no-op without a serial, otherwise run via run().
    const act = (msg: RowMessages, fn: () => Promise<unknown>) => () => {
      if (serial) void run(msg, fn);
    };
    return certKebabItems(cert, {
      onRekey: act({ fail: "Rekey failed" }, async () => { await backfillTypeIfMissing(cert); await rekeyAndGo(navigate, serial!); }),
      onRenew: act({ fail: "Renew failed" }, async () => { await backfillTypeIfMissing(cert); await renewAndGo(navigate, serial!); }),
      onRevoke: () => setRevokeTarget(cert),
      onIgnore: () => setIgnoreTarget(cert),
      onUnignore: act({ fail: "Unignore failed", ok: `Unignored ${label}` }, async () => {
        await unignoreCert(serial!);
        await finishListAction(cert);
      }),
    });
  }

  const [inspectPem, setInspectPem] = createSignal("");
  const [inspecting, setInspecting] = createSignal(false);
  const [inspectError, setInspectError] = createSignal<string | null>(null);
  const [inspectResult, setInspectResult] = createSignal<InspectCertificateResult | null>(null);
  const [inspectCopied, markInspectCopied] = createCopiedSignal();

  async function handleInspect() {
    const pem = inspectPem().trim();
    setInspectError(null);
    setInspectResult(null);
    if (!pem) {
      setInspectError("Certificate PEM is required.");
      return;
    }
    setInspecting(true);
    try {
      const result = await inspectCertificate(pem);
      setInspectResult(result);
    } catch (e) {
      setInspectError(String(e));
    } finally {
      setInspecting(false);
    }
  }

  function copyInspectDump() {
    const dump = inspectResult()?.text_dump;
    if (dump) {
      void writeClipboard(dump);
      markInspectCopied();
    }
  }

  async function handleGenerateCsr(cert: ExternalCertListItem, e: MouseEvent) {
    e.stopPropagation();
    if (!cert.serial) return;
    const ok = window.confirm(
      `Generate a fresh CSR (new key, same subject and SANs) from ${cert.cn ?? cert.serial}?\n\nThe new CSR will appear as a Pending CSR you can send to your external CA.`,
    );
    if (!ok) return;

    setGenerateError(null);
    setGeneratingSerial(cert.serial);
    try {
      await generateCsrFromCert({ serial: cert.serial });
      navigate("/csrs");
    } catch (err) {
      setGenerateError(String(err));
    } finally {
      setGeneratingSerial(null);
    }
  }

  return (
    <div class="page-certs">
      <div class="page-header">
        <h2>Certificates</h2>
        <div class="header-actions">
          {/* Search/filter/Refresh apply only to the list tabs. Import stays
              visible on every tab so the header keeps a constant height and the
              tabs/table below don't shift when switching to Inspect. */}
          <Show when={tab() !== "inspect"}>
            <SearchInput value={search()} onInput={setSearch} />
            <select
              class="status-filter"
              value={filter()}
              onChange={(e) => { setFilter(e.currentTarget.value); sessionFilter = e.currentTarget.value; }}
            >
              <option value="all">All</option>
              <option value="valid">Valid</option>
              <option value="expiring">Expiring Soon</option>
              <option value="expired">Expired</option>
              <option value="revoked">Revoked</option>
              <option value="superseded">Superseded</option>
              <option value="ignored">Ignored</option>
            </select>
            <button class="btn-ghost" onClick={handleRefresh} disabled={loading()}>
              {loading() ? "Loading\u2026" : "Refresh"}
            </button>
            <Show when={tab() === "local"}>
              <button class="btn-primary" onClick={() => navigate("/certs/create")}>
                Create
              </button>
            </Show>
          </Show>
          <button class="btn-secondary" onClick={() => navigate("/certs/import")}>
            Import
          </button>
        </div>
      </div>

      <div class="tab-bar">
        <button
          class={`tab-btn ${tab() === "local" ? "tab-active" : ""}`}
          onClick={() => setTab("local")}
        >
          Local
        </button>
        <button
          class={`tab-btn ${tab() === "external" ? "tab-active" : ""}`}
          onClick={() => { setTab("external"); sel.clear(); }}
        >
          External
        </button>
        <button
          class={`tab-btn ${tab() === "inspect" ? "tab-active" : ""}`}
          onClick={() => { setTab("inspect"); setInspectError(null); sel.clear(); }}
        >
          Inspect
        </button>
      </div>

      <Show when={certs().error}>
        <p class="page-error" role="alert">{String(certs().error)}</p>
      </Show>

      <Show when={loading()}>
        <Spinner message="Loading…" />
      </Show>

      {/* Local certificates tab */}
      <Show when={tab() === "local"}>
        <ActionResultBanner outcome={outcome} />

        <Show when={bulkResults()}>
          {(results) => (
            <ResultBanner
              results={results().map((r) => ({ id: r.serial, ok: r.ok, error: r.error }))}
              onDismiss={() => setBulkResults(null)}
            />
          )}
        </Show>

        <Show when={sel.selected().size > 0}>
          <div class="bulk-action-bar">
            <span class="bulk-count">{sel.selected().size} selected</span>
            <button class="btn-secondary btn-sm" disabled={!canRekey()} onClick={() => setBulkAction("rekey")}>Rekey</button>
            <button
              class="btn-secondary btn-sm"
              disabled={!canRenewOrRevoke()}
              title={canRenewOrRevoke() ? undefined : "All selected certs must be Valid"}
              onClick={() => setBulkAction("renew")}
            >Renew</button>
            <button
              class="btn-danger btn-sm"
              disabled={!canRenewOrRevoke()}
              title={canRenewOrRevoke() ? undefined : "All selected certs must be Valid"}
              onClick={() => setBulkAction("revoke")}
            >Revoke</button>
            <button
              class="btn-secondary btn-sm"
              disabled={!canIgnore()}
              title={canIgnore() ? undefined : "All selected certs must be Expired or Expiring and not already ignored"}
              onClick={() => setBulkAction("ignore")}
            >Ignore</button>
            <button class="btn-ghost btn-sm" onClick={sel.clear}>Clear</button>
          </div>
        </Show>

        <Show when={!localCerts.loading && filteredLocal().length === 0}>
          <p class="text-muted mt-3">
            No local certificates found.
          </p>
        </Show>

        <Show when={filteredLocal().length > 0}>
          <div class="data-table-wrap">
            <table class="data-table">
              <thead>
                <tr>
                  <th class="checkbox-col">
                    <SelectAllCheckbox all={sel.allSelected()} some={sel.someSelected()} onToggle={sel.toggleAll} />
                  </th>
                  <th>Serial</th>
                  <th>Common Name</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Expiry <TzToggle /></th>
                  <th class="kebab-col"></th>
                </tr>
              </thead>
              <tbody>
                <For each={filteredLocal()}>
                  {(cert) => (
                    <tr
                      class="data-table-row"
                      classList={{
                        "data-table-row-ignored":
                          !!cert.ignored_at || !!cert.superseded_by,
                        "data-table-row-selected":
                          !!cert.serial && sel.isSelected(cert.serial),
                      }}
                      onClick={() => cert.serial && navigate(`/certs/${cert.serial}`)}
                    >
                      <td class="checkbox-col" onClick={(e) => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          class="table-checkbox"
                          checked={!!cert.serial && sel.isSelected(cert.serial)}
                          disabled={!cert.serial}
                          onChange={() => cert.serial && sel.toggle(cert.serial)}
                          aria-label={`Select ${cert.cn ?? cert.serial ?? "certificate"}`}
                        />
                      </td>
                      <td class="mono">{cert.serial ?? "\u2014"}</td>
                      <td>{cert.cn ?? "\u2014"}</td>
                      <td>{cert.cert_type ?? "\u2014"}</td>
                      <td>
                        <CertStatusBadge status={cert.status} expiringSoon={cert.expiring_soon} />
                        <Show when={cert.ignored_at}>
                          <span class="status-badge status-ignored">ignored</span>
                        </Show>
                        <Show when={cert.superseded_by && !cert.ignored_at}>
                          <span class="status-badge status-superseded">superseded</span>
                        </Show>
                      </td>
                      <td class="mono">{formatDate(cert.expiry_date)}</td>
                      <td class="kebab-col" onClick={(e) => e.stopPropagation()}>
                        <KebabMenu items={certMenuItems(cert)} />
                      </td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </div>
        </Show>
      </Show>

      {/* External certificates tab */}
      <Show when={tab() === "external"}>
        <Show when={!externalCerts.loading && filteredExternal().length === 0}>
          <p class="text-muted mt-3">
            No external certificates found.
          </p>
        </Show>

        <Show when={generateError()}>
          <p class="page-error" role="alert">{generateError()}</p>
        </Show>

        <Show when={filteredExternal().length > 0}>
          <div class="data-table-wrap">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Serial</th>
                  <th>Common Name</th>
                  <th>Issuer</th>
                  <th>Status</th>
                  <th>Expiry <TzToggle /></th>
                  <th>Imported</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                <For each={filteredExternal()}>
                  {(cert) => (
                    <tr
                      class="data-table-row"
                      onClick={() => cert.serial && navigate(`/external-certs/${cert.serial}`)}
                    >
                      <td class="mono">{cert.serial ?? "\u2014"}</td>
                      <td>{cert.cn ?? "\u2014"}</td>
                      <td>{cert.issuer ?? "\u2014"}</td>
                      <td><span class={statusBadgeClass(cert.status)}>{cert.status ?? "\u2014"}</span></td>
                      <td class="mono">{formatDate(cert.expiry_date)}</td>
                      <td class="mono">{formatDate(cert.import_date)}</td>
                      <td>
                        <button
                          class="btn-ghost btn-sm"
                          disabled={generatingSerial() !== null}
                          onClick={(e) => handleGenerateCsr(cert, e)}
                        >
                          {generatingSerial() === cert.serial ? "Generating\u2026" : "Generate CSR"}
                        </button>
                      </td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </div>
        </Show>
      </Show>

      {/* \u2500\u2500 Inspect tab \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 */}
      <Show when={tab() === "inspect"}>
        <div class="form-group">
          <label class="form-label">Certificate PEM</label>
          <textarea
            rows={10}
            placeholder="Paste a certificate PEM here…"
            value={inspectPem()}
            onInput={(e) => {
              setInspectPem(e.currentTarget.value);
              setInspectResult(null);
              setInspectError(null);
            }}
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            spellcheck={false}
          />
        </div>

        <div class="form-actions">
          <button
            class="btn-primary"
            type="button"
            disabled={inspecting() || !inspectPem().trim()}
            onClick={handleInspect}
          >
            {inspecting() ? "Inspecting\u2026" : "Inspect Certificate"}
          </button>
        </div>

        <Show when={inspectError()}>
          <p class="page-error" role="alert">{inspectError()}</p>
        </Show>

        <Show when={inspectResult()}>
          {(r) => (
            <div class="detail-section">
              <div class="detail-grid">
                <div class="detail-row">
                  <span class="detail-label">Common Name</span>
                  <span class="detail-value">{r().cn ?? "\u2014"}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Subject</span>
                  <span class="detail-value mono">{r().subject || "\u2014"}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Issuer</span>
                  <span class="detail-value mono">{r().issuer || "\u2014"}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Serial</span>
                  <span class="detail-value mono">{r().serial ?? "\u2014"}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Valid From <TzToggle /></span>
                  <span class="detail-value mono">{formatDate(r().not_before)}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Valid Until</span>
                  <span class="detail-value mono">{formatDate(r().not_after)}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Key</span>
                  <span class="detail-value">{r().key_type} {r().key_size} bits</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Signature Algorithm</span>
                  <span class="detail-value mono">{r().signature_algorithm}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Public Key SHA-256</span>
                  <span class="detail-value mono">{r().public_key_fingerprint_sha256}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">CA Certificate</span>
                  <span class="detail-value">{r().is_ca ? "Yes" : "No"}</span>
                </div>
              </div>

              <div class="form-group">
                <label class="form-label">Subject Alternative Names</label>
                <Show when={r().alt_dns_names.length > 0} fallback={
                  <p class="text-muted text-sm">No alternative names.</p>
                }>
                  <div class="san-list">
                    <For each={r().alt_dns_names}>
                      {(san) => <span class="san-tag">{san}</span>}
                    </For>
                  </div>
                </Show>
              </div>

              <div class="pem-section">
                <div class="pem-header">
                  <span class="detail-label">Text Dump</span>
                  <button
                    type="button"
                    class="btn-ghost btn-sm"
                    onClick={copyInspectDump}
                  >
                    {inspectCopied() ? "Copied" : "Copy"}
                  </button>
                </div>
                <pre class="text-dump mono">{r().text_dump}</pre>
              </div>
            </div>
          )}
        </Show>
      </Show>

      <IgnoreCertDialog
        open={!!ignoreTarget()}
        serial={ignoreTarget()?.serial ?? null}
        cn={ignoreTarget()?.cn ?? null}
        onClose={() => setIgnoreTarget(null)}
        onDone={() => { const c = ignoreTarget(); if (c) { outcome.report(`Ignored ${certLabel(c)}`); void finishListAction(c); } }}
      />

      <RevokeCertDialog
        open={!!revokeTarget()}
        serial={revokeTarget()?.serial ?? null}
        cn={revokeTarget()?.cn ?? null}
        onClose={() => setRevokeTarget(null)}
        onDone={() => { const c = revokeTarget(); if (c) { outcome.report(`Revoked ${certLabel(c)}`); void finishListAction(c); } }}
      />

      <BulkConfirmDialog
        open={!!bulkAction()}
        title={bulkDialogConfig().title}
        message={bulkDialogConfig().message}
        confirmLabel={bulkDialogConfig().confirmLabel}
        actingLabel={bulkDialogConfig().actingLabel}
        danger={bulkDialogConfig().danger}
        requireReason={bulkDialogConfig().requireReason}
        onClose={() => setBulkAction(null)}
        onConfirm={runBulk}
      />

    </div>
  );
}
