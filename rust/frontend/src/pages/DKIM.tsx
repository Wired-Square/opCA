import { Show, For, createSignal, createResource } from "solid-js";
import { listDkimKeys, getDkimInfo, createDkimKey, deleteDkimKey, verifyDkimDns, deployDkimRoute53 } from "../api/dkim";
import { formatDate } from "../utils/dates";
import Spinner from "../components/Spinner";
import SearchInput from "../components/SearchInput";
import type { DkimKeyItem, DkimKeyDetail, DkimVerifyResult } from "../api/types";

type Tab = "keys" | "create";

export default function DKIM() {
  const [tab, setTab] = createSignal<Tab>("keys");
  const [keys, { refetch }] = createResource<DkimKeyItem[]>(listDkimKeys);
  const [selected, setSelected] = createSignal<DkimKeyItem | null>(null);
  const [detail, setDetail] = createSignal<DkimKeyDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = createSignal(false);
  const [acting, setActing] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [success, setSuccess] = createSignal<string | null>(null);
  const [copied, setCopied] = createSignal(false);

  const [search, setSearch] = createSignal("");

  const filteredKeys = () => {
    const items = keys() ?? [];
    const q = search().toLowerCase();
    if (!q) return items;
    return items.filter((k) =>
      [k.domain, k.selector, k.created_at].some((v) => v?.toLowerCase().includes(q))
    );
  };

  // Create form signals
  const [domain, setDomain] = createSignal("");
  const [selector, setSelector] = createSignal("");
  const [creating, setCreating] = createSignal(false);
  const [createError, setCreateError] = createSignal<string | null>(null);
  const [createResult, setCreateResult] = createSignal<{ domain: string; selector: string; dns_name: string; dns_record: string } | null>(null);

  // Route53 deploy
  const [deploying, setDeploying] = createSignal(false);

  // Confirm delete
  const [confirmDelete, setConfirmDelete] = createSignal(false);

  function selectRow(key: DkimKeyItem) {
    setSelected(key);
    setDetail(null);
    setError(null);
    setSuccess(null);
    setConfirmDelete(false);
  }

  async function handleInfo() {
    const sel = selected();
    if (!sel) return;
    setLoadingDetail(true);
    setError(null);
    setDetail(null);
    try {
      const info = await getDkimInfo(sel.domain, sel.selector);
      setDetail(info);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoadingDetail(false);
    }
  }

  async function handleVerify() {
    const sel = selected();
    if (!sel) return;
    setActing(true);
    setError(null);
    setSuccess(null);
    try {
      const result: DkimVerifyResult = await verifyDkimDns(sel.domain, sel.selector);
      if (result.verified) {
        setSuccess(result.message);
      } else {
        setError(result.message);
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setActing(false);
    }
  }

  async function handleDeployRoute53() {
    const sel = selected();
    if (!sel) return;
    setDeploying(true);
    setError(null);
    setSuccess(null);
    try {
      const result = await deployDkimRoute53(sel.domain, sel.selector);
      setSuccess(result.message);
    } catch (e) {
      setError(String(e));
    } finally {
      setDeploying(false);
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
      setCreateError(null);
      setSuccess(result.message);
      setTab("keys");
    } catch (e) {
      setCreateError(String(e));
    } finally {
      setDeploying(false);
    }
  }

  async function handleDelete() {
    const sel = selected();
    if (!sel) return;
    setActing(true);
    setError(null);
    try {
      await deleteDkimKey(sel.domain, sel.selector);
      setSelected(null);
      setDetail(null);
      setConfirmDelete(false);
      refetch();
    } catch (e) {
      setError(String(e));
    } finally {
      setActing(false);
    }
  }

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
      setCreateResult({ domain: d, selector: s, dns_name: result.dns_name, dns_record: result.dns_record });
      setDomain("");
      setSelector("");
      refetch();
    } catch (err) {
      setCreateError(String(err));
    } finally {
      setCreating(false);
    }
  }

  function copyDnsRecord() {
    const rec = detail()?.dns_record ?? createResult()?.dns_record;
    if (rec) {
      navigator.clipboard.writeText(rec);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }

  return (
    <div class="page-dkim">
      <div class="page-header">
        <h2>DKIM Key Management</h2>
        <Show when={tab() === "keys"}>
          <div class="header-actions">
            <SearchInput value={search()} onInput={setSearch} />
            <button class="btn-ghost" onClick={() => refetch()} disabled={keys.loading}>
              Refresh
            </button>
          </div>
        </Show>
      </div>

      <div class="tab-bar">
        <button
          class={`tab-btn ${tab() === "keys" ? "tab-active" : ""}`}
          onClick={() => { setTab("keys"); setError(null); setSuccess(null); }}
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
          <Show when={keys.loading}>
            <Spinner message="Loading DKIM keys..." />
          </Show>

          <Show when={keys.error}>
            <p class="page-error">{String(keys.error)}</p>
          </Show>

          <Show when={!keys.loading && filteredKeys().length === 0}>
            <p class="text-muted">No DKIM keys found.</p>
          </Show>

          <Show when={filteredKeys().length > 0}>
            <div class="dkim-table-wrap">
              <table class="dkim-table">
                <thead>
                  <tr>
                    <th>Domain</th>
                    <th>Selector</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={filteredKeys()}>
                    {(key) => (
                      <tr
                        class={`dkim-row ${selected()?.domain === key.domain && selected()?.selector === key.selector ? "dkim-row-selected" : ""}`}
                        onClick={() => selectRow(key)}
                      >
                        <td>{key.domain}</td>
                        <td class="mono">{key.selector}</td>
                        <td class="mono">{formatDate(key.created_at)}</td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </Show>

          <Show when={selected()}>
            <div class="key-actions">
              <button class="btn-secondary" onClick={handleInfo} disabled={loadingDetail() || acting()}>
                {loadingDetail() ? "Loading..." : "Info"}
              </button>
              <button class="btn-secondary" onClick={handleVerify} disabled={acting() || deploying()}>
                {acting() ? "Verifying..." : "Verify DNS"}
              </button>
              <button class="btn-secondary" onClick={handleDeployRoute53} disabled={acting() || deploying()}>
                {deploying() ? "Deploying..." : "Deploy to Route53"}
              </button>
              <Show when={!confirmDelete()}>
                <button class="btn-danger" onClick={() => setConfirmDelete(true)} disabled={acting()}>
                  Delete
                </button>
              </Show>
              <Show when={confirmDelete()}>
                <span class="text-warning">Are you sure?</span>
                <button class="btn-danger" onClick={handleDelete} disabled={acting()}>
                  {acting() ? "Deleting..." : "Confirm Delete"}
                </button>
                <button class="btn-ghost" onClick={() => setConfirmDelete(false)}>Cancel</button>
              </Show>
            </div>
          </Show>

          <Show when={error()}>
            <p class="page-error">{error()}</p>
          </Show>

          <Show when={success()}>
            <p class="page-success">{success()}</p>
          </Show>

          <Show when={loadingDetail()}>
            <Spinner message="Fetching key details from vault..." />
          </Show>

          <Show when={detail()}>
            {(d) => (
              <div class="detail-grid">
                <Row label="Domain" value={d().domain} />
                <Row label="Selector" value={d().selector} mono />
                <Row label="Key Size" value={d().key_size ? `${d().key_size} bits` : null} />
                <Row label="DNS Name" value={d().dns_name} mono />
                <Row label="Created" value={d().created_at} />
                <Show when={d().dns_record}>
                  <div class="detail-row">
                    <span class="detail-label">DNS Record</span>
                    <div class="dns-record-wrap">
                      <pre class="dns-record mono">{d().dns_record}</pre>
                      <button class="btn-ghost btn-sm" onClick={copyDnsRecord}>
                        {copied() ? "Copied" : "Copy"}
                      </button>
                    </div>
                  </div>
                </Show>
              </div>
            )}
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
              <p class="page-error">{createError()}</p>
            </Show>

            <Show when={createResult()}>
              {(r) => (
                <div class="create-success">
                  <p class="page-success">DKIM key created successfully.</p>
                  <div class="detail-grid">
                    <Row label="DNS Name" value={r().dns_name} mono />
                    <div class="detail-row">
                      <span class="detail-label">DNS Record</span>
                      <div class="dns-record-wrap">
                        <pre class="dns-record mono">{r().dns_record}</pre>
                        <button type="button" class="btn-ghost btn-sm" onClick={copyDnsRecord}>
                          {copied() ? "Copied" : "Copy"}
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </Show>

            <div class="form-actions">
              <Show when={!createResult()} fallback={
                <button class="btn-primary" type="button" onClick={handleDeployCreated} disabled={deploying()}>
                  {deploying() ? "Deploying..." : "Deploy to Route53"}
                </button>
              }>
                <button class="btn-primary" type="submit" disabled={creating() || !domain().trim() || !selector().trim()}>
                  {creating() ? "Creating..." : "Create DKIM Key"}
                </button>
              </Show>
            </div>
          </form>
        </div>
      </Show>

      <style>{`
        .page-dkim {
          padding: 32px;
          display: flex;
          flex-direction: column;
          height: 100%;
          box-sizing: border-box;
        }

        .page-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 16px;
          flex-shrink: 0;
        }

        .page-header h2 {
          margin: 0;
        }

        .header-actions {
          display: flex;
          gap: 8px;
          align-items: center;
        }

        .page-error {
          color: var(--error);
          font-size: 0.875rem;
          padding: 8px 12px;
          background: rgba(255, 69, 58, 0.1);
          border-radius: 6px;
          margin-top: 12px;
        }

        .page-success {
          color: var(--success);
          font-size: 0.875rem;
          padding: 8px 12px;
          background: rgba(34, 197, 94, 0.1);
          border-radius: 6px;
          margin-top: 12px;
        }

        .dkim-table-wrap {
          border: 1px solid var(--border);
          border-radius: 10px;
          overflow: auto;
          max-height: 240px;
        }

        .dkim-table {
          width: 100%;
          border-collapse: collapse;
          font-size: 0.875rem;
        }

        .dkim-table th {
          text-align: left;
          padding: 10px 14px;
          font-size: 0.75rem;
          font-weight: 600;
          text-transform: uppercase;
          letter-spacing: 0.05em;
          color: var(--text-secondary);
          background: var(--bg-elevated);
          border-bottom: 1px solid var(--border);
          position: sticky;
          top: 0;
          z-index: 1;
        }

        .dkim-table td {
          padding: 10px 14px;
          border-bottom: 1px solid var(--border);
          color: var(--text-primary);
        }

        .dkim-row {
          cursor: pointer;
          transition: background 0.1s;
        }

        .dkim-row:hover {
          background: var(--bg-elevated);
        }

        .dkim-row-selected {
          background: var(--accent-glow) !important;
        }

        .dkim-row:last-child td {
          border-bottom: none;
        }

        .key-actions {
          display: flex;
          align-items: center;
          gap: 8px;
          margin-top: 16px;
        }

        .detail-grid {
          display: grid;
          gap: 8px;
          margin-top: 16px;
        }

        .detail-row {
          display: flex;
          gap: 16px;
          padding: 6px 12px;
          border-radius: 6px;
        }

        .detail-row:nth-child(odd) {
          background: var(--bg-elevated);
        }

        .detail-label {
          min-width: 120px;
          font-size: 0.8125rem;
          font-weight: 500;
          color: var(--text-secondary);
          flex-shrink: 0;
        }

        .detail-value {
          font-size: 0.875rem;
          color: var(--text-primary);
          word-break: break-all;
        }

        .dns-record-wrap {
          flex: 1;
          min-width: 0;
        }

        .dns-record {
          padding: 10px 12px;
          background: var(--bg-surface);
          border: 1px solid var(--border);
          border-radius: 6px;
          font-size: 0.6875rem;
          line-height: 1.5;
          white-space: pre-wrap;
          word-break: break-all;
          margin-bottom: 4px;
        }

        .create-form {
          max-width: 480px;
          display: flex;
          flex-direction: column;
          gap: 16px;
        }

        .form-group {
          display: flex;
          flex-direction: column;
          gap: 6px;
        }

        .form-label {
          font-size: 0.8125rem;
          font-weight: 500;
          color: var(--text-secondary);
        }

        .form-actions {
          display: flex;
          gap: 12px;
          margin-top: 4px;
        }

        .create-success {
          margin-top: 8px;
        }

        .btn-danger {
          padding: 8px 16px;
          background: var(--error);
          color: white;
          border: none;
          border-radius: 8px;
          font-weight: 600;
          cursor: pointer;
          font-size: 0.875rem;
        }

        .btn-danger:hover {
          opacity: 0.9;
        }

        .btn-danger:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }

        .btn-sm {
          padding: 4px 10px;
          font-size: 0.75rem;
        }
      `}</style>
    </div>
  );
}

function Row(props: {
  label: string;
  value: string | null | undefined;
  mono?: boolean;
}) {
  return (
    <div class="detail-row">
      <span class="detail-label">{props.label}</span>
      <span class={`detail-value ${props.mono ? "mono" : ""}`}>
        {props.value ?? "\u2014"}
      </span>
    </div>
  );
}
