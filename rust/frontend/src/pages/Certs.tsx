import { Show, For, createSignal, createResource } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { listCerts, listExternalCerts } from "../api/certs";
import { formatDate } from "../utils/dates";
import TzToggle from "../components/TzToggle";
import Spinner from "../components/Spinner";
import SearchInput from "../components/SearchInput";
import type { CertListItem, ExternalCertListItem } from "../api/types";
import "../styles/pages/certs.css";

type Tab = "local" | "external";

export default function Certs() {
  const navigate = useNavigate();
  const [tab, setTab] = createSignal<Tab>("local");
  const [filter, setFilter] = createSignal("all");
  const [search, setSearch] = createSignal("");

  const [localCerts, { refetch: refetchLocal }] = createResource<CertListItem[]>(listCerts);
  const [externalCerts, { refetch: refetchExternal }] = createResource<ExternalCertListItem[]>(listExternalCerts);

  const certs = () => (tab() === "local" ? localCerts : externalCerts);
  const loading = () => certs().loading;

  const filteredLocal = () => {
    let items = localCerts() ?? [];
    const f = filter();
    if (f !== "all") items = items.filter((c) => c.status?.toLowerCase() === f);
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

  return (
    <div class="page-certs">
      <div class="page-header">
        <h2>Certificates</h2>
        <div class="header-actions">
          <SearchInput value={search()} onInput={setSearch} />
          <select
            class="status-filter"
            value={filter()}
            onChange={(e) => setFilter(e.currentTarget.value)}
          >
            <option value="all">All</option>
            <option value="valid">Valid</option>
            <option value="expired">Expired</option>
            <option value="revoked">Revoked</option>
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
      </div>

      <Show when={certs().error}>
        <p class="page-error">{String(certs().error)}</p>
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
                      onClick={() => cert.serial && navigate(`/certs/${cert.serial}`)}
                    >
                      <td class="mono">{cert.serial ?? "\u2014"}</td>
                      <td>{cert.cn ?? "\u2014"}</td>
                      <td>{cert.cert_type ?? "\u2014"}</td>
                      <td><span class={statusBadgeClass(cert.status)}>{cert.status ?? "\u2014"}</span></td>
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
                </tr>
              </thead>
              <tbody>
                <For each={filteredExternal()}>
                  {(cert) => (
                    <tr class="data-table-row">
                      <td class="mono">{cert.serial ?? "\u2014"}</td>
                      <td>{cert.cn ?? "\u2014"}</td>
                      <td>{cert.issuer ?? "\u2014"}</td>
                      <td><span class={statusBadgeClass(cert.status)}>{cert.status ?? "\u2014"}</span></td>
                      <td class="mono">{formatDate(cert.expiry_date)}</td>
                      <td class="mono">{formatDate(cert.import_date)}</td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </div>
        </Show>
      </Show>

    </div>
  );
}
