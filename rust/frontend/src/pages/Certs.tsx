import { Show, For, createSignal, createResource } from "solid-js";
import { useNavigate, useSearchParams } from "@solidjs/router";
import { listCerts, listExternalCerts, inspectCertificate } from "../api/certs";
import { generateCsrFromCert } from "../api/csr";
import { formatDate } from "../utils/dates";
import { createCopiedSignal, writeClipboard } from "../utils/clipboard";
import TzToggle from "../components/TzToggle";
import Spinner from "../components/Spinner";
import SearchInput from "../components/SearchInput";
import CertStatusBadge from "../components/CertStatusBadge";
import type { CertListItem, ExternalCertListItem, InspectCertificateResult } from "../api/types";
import "../styles/pages/certs.css";

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

export default function Certs() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const initialFilter = typeof searchParams.filter === "string" && VALID_FILTERS.has(searchParams.filter)
    ? searchParams.filter
    : "valid";
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
          <Show when={tab() !== "inspect"}>
            <SearchInput value={search()} onInput={setSearch} />
            <select
              class="status-filter"
              value={filter()}
              onChange={(e) => setFilter(e.currentTarget.value)}
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
            <button class="btn-secondary" onClick={() => navigate("/certs/import")}>
              Import
            </button>
          </Show>
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
          onClick={() => setTab("external")}
        >
          External
        </button>
        <button
          class={`tab-btn ${tab() === "inspect" ? "tab-active" : ""}`}
          onClick={() => { setTab("inspect"); setInspectError(null); }}
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
                  <th>Serial</th>
                  <th>Common Name</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Expiry <TzToggle /></th>
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
                      }}
                      onClick={() => cert.serial && navigate(`/certs/${cert.serial}`)}
                    >
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

    </div>
  );
}
