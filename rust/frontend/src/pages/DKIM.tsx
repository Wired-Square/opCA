import { Show, For, createSignal, createResource } from "solid-js";
import { useNavigate } from "@solidjs/router";
import {
  listDkimKeys,
  syncDkimKeys,
  createDkimKey,
  deployDkimRoute53,
} from "../api/dkim";
import { formatDate } from "../utils/dates";
import { createCopiedSignal } from "../utils/clipboard";
import Spinner from "../components/Spinner";
import SearchInput from "../components/SearchInput";
import type { DkimKeyItem } from "../api/types";
import "../styles/pages/dkim.css";

type Tab = "keys" | "create";

export default function DKIM() {
  const navigate = useNavigate();
  const [tab, setTab] = createSignal<Tab>("keys");
  // listDkimKeys self-syncs from 1Password the first time after migration
  // (when the dkim_key table is empty), so a separate onMount sync would
  // duplicate the work and run a vault upload on every page visit.
  const [keys, { refetch }] = createResource<DkimKeyItem[]>(listDkimKeys);
  const [syncing, setSyncing] = createSignal(false);
  const [syncError, setSyncError] = createSignal<string | null>(null);
  const [search, setSearch] = createSignal("");
  const [copied, markCopied] = createCopiedSignal();

  async function handleRefresh() {
    setSyncing(true);
    setSyncError(null);
    try {
      await syncDkimKeys();
      refetch();
    } catch (e) {
      setSyncError(String(e));
    } finally {
      setSyncing(false);
    }
  }

  const filteredKeys = () => {
    const items = keys() ?? [];
    const q = search().toLowerCase();
    if (!q) return items;
    return items.filter((k) =>
      [k.domain, k.selector, k.created_at].some((v) => v?.toLowerCase().includes(q)),
    );
  };

  // Create form
  const [domain, setDomain] = createSignal("");
  const [selector, setSelector] = createSignal("");
  const [creating, setCreating] = createSignal(false);
  const [createError, setCreateError] = createSignal<string | null>(null);
  const [createResult, setCreateResult] = createSignal<{
    domain: string;
    selector: string;
    dns_name: string;
    dns_record: string;
    dns_record_chunked: string;
  } | null>(null);
  const [chunked, setChunked] = createSignal(false);
  const [deploying, setDeploying] = createSignal(false);
  const [success, setSuccess] = createSignal<string | null>(null);

  async function handleCreate(e: Event) {
    e.preventDefault();
    const d = domain().trim();
    const s = selector().trim();
    setCreateError(null);
    setCreateResult(null);

    if (!d || !s) {
      setCreateError("Domain and selector are required.");
      return;
    }

    setCreating(true);
    try {
      const result = await createDkimKey({ domain: d, selector: s });
      setCreateResult({
        domain: d,
        selector: s,
        dns_name: result.dns_name,
        dns_record: result.dns_record,
        dns_record_chunked: result.dns_record_chunked,
      });
      setDomain("");
      setSelector("");
      refetch();
    } catch (err) {
      setCreateError(String(err));
    } finally {
      setCreating(false);
    }
  }

  async function handleDeployCreated() {
    const r = createResult();
    if (!r) return;
    setDeploying(true);
    setCreateError(null);
    try {
      const result = await deployDkimRoute53(r.domain, r.selector);
      setCreateResult(null);
      setSuccess(result.message);
      setTab("keys");
    } catch (e) {
      setCreateError(String(e));
    } finally {
      setDeploying(false);
    }
  }

  function copyDnsRecord() {
    const r = createResult();
    if (!r) return;
    const value = chunked() ? r.dns_record_chunked : r.dns_record;
    navigator.clipboard.writeText(value);
    markCopied();
  }

  return (
    <div class="page-dkim">
      <div class="page-header">
        <h2>DKIM Key Management</h2>
        <Show when={tab() === "keys"}>
          <div class="header-actions">
            <SearchInput value={search()} onInput={setSearch} />
            <button class="btn-ghost" onClick={handleRefresh} disabled={keys.loading || syncing()}>
              {syncing() ? "Syncing…" : "Refresh"}
            </button>
          </div>
        </Show>
      </div>

      <div class="tab-bar">
        <button
          class={`tab-btn ${tab() === "keys" ? "tab-active" : ""}`}
          onClick={() => setTab("keys")}
        >
          Keys
        </button>
        <button
          class={`tab-btn ${tab() === "create" ? "tab-active" : ""}`}
          onClick={() => { setTab("create"); setCreateError(null); setCreateResult(null); }}
        >
          Create
        </button>
      </div>

      {/* ── Keys Tab ──────────────────────────────────────────────── */}
      <Show when={tab() === "keys"}>
        <div class="tab-content">
          <Show when={keys.loading || syncing()}>
            <Spinner message={syncing() ? "Syncing DKIM keys from vault…" : "Loading DKIM keys…"} />
          </Show>

          <Show when={syncError()}>
            <p class="page-error" role="alert">{syncError()}</p>
          </Show>

          <Show when={keys.error}>
            <p class="page-error" role="alert">{String(keys.error)}</p>
          </Show>

          <Show when={success()}>
            <p class="page-success">{success()}</p>
          </Show>

          <Show when={!keys.loading && !syncing() && filteredKeys().length === 0}>
            <p class="text-muted">No DKIM keys found.</p>
          </Show>

          <Show when={filteredKeys().length > 0}>
            <div class="data-table-wrap">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>Domain</th>
                    <th>Selector</th>
                    <th>Key Size</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={filteredKeys()}>
                    {(key) => (
                      <tr
                        class="data-table-row"
                        onClick={() => navigate(`/dkim/${encodeURIComponent(key.domain)}/${encodeURIComponent(key.selector)}`)}
                      >
                        <td>{key.domain}</td>
                        <td class="mono">{key.selector}</td>
                        <td class="mono">{key.key_size != null ? `${key.key_size}` : "—"}</td>
                        <td class="mono">{formatDate(key.created_at)}</td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </Show>
        </div>
      </Show>

      {/* ── Create Tab ────────────────────────────────────────────── */}
      <Show when={tab() === "create"}>
        <div class="tab-content">
          <form class="create-form" onSubmit={handleCreate}>
            <div class="form-group">
              <label class="form-label">Domain</label>
              <input
                type="text"
                placeholder="e.g. example.com"
                value={domain()}
                onInput={(e) => setDomain(e.currentTarget.value)}
                autocomplete="off"
                autocorrect="off"
                autocapitalize="off"
                spellcheck={false}
              />
            </div>

            <div class="form-group">
              <label class="form-label">Selector</label>
              <input
                type="text"
                placeholder="e.g. mail"
                value={selector()}
                onInput={(e) => setSelector(e.currentTarget.value)}
                autocomplete="off"
                autocorrect="off"
                autocapitalize="off"
                spellcheck={false}
              />
            </div>

            <Show when={createError()}>
              <p class="page-error" role="alert">{createError()}</p>
            </Show>

            <Show when={createResult()}>
              {(r) => (
                <div class="create-success">
                  <p class="page-success">DKIM key created successfully.</p>
                  <div class="detail-grid">
                    <div class="detail-row">
                      <span class="detail-label">DNS Name</span>
                      <span class="detail-value mono">{r().dns_name}</span>
                    </div>
                    <div class="detail-row">
                      <span class="detail-label">DNS Record</span>
                      <div class="dns-record-wrap">
                        <pre class="dns-record mono">
                          {chunked() ? r().dns_record_chunked : r().dns_record}
                        </pre>
                        <div class="dns-record-actions">
                          <button
                            type="button"
                            class="btn-ghost btn-sm"
                            onClick={() => setChunked((v) => !v)}
                            title="Format as 255-byte chunks for AWS Route53"
                            aria-pressed={chunked()}
                          >
                            {chunked() ? "Single" : "AWS chunks"}
                          </button>
                          <button type="button" class="btn-ghost btn-sm" onClick={copyDnsRecord}>
                            {copied() ? "Copied" : "Copy"}
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </Show>

            <div class="form-actions">
              <Show when={!createResult()} fallback={
                <button class="btn-primary" type="button" onClick={handleDeployCreated} disabled={deploying()}>
                  {deploying() ? "Deploying…" : "Deploy to Route53"}
                </button>
              }>
                <button class="btn-primary" type="submit" disabled={creating() || !domain().trim() || !selector().trim()}>
                  {creating() ? "Creating…" : "Create DKIM Key"}
                </button>
              </Show>
            </div>
          </form>
        </div>
      </Show>

    </div>
  );
}
