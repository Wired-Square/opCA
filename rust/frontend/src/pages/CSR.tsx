import { Show, For, createSignal, createResource } from "solid-js";
import { listCsrs, getCsrInfo, createCsr, decodeCsr, signCsr } from "../api/csr";
import Spinner from "../components/Spinner";
import SearchInput from "../components/SearchInput";
import { CERT_TYPES } from "../api/types";
import type { CsrListItem, CreateCsrResult, DecodeCsrResult, SignCsrResult } from "../api/types";

type Tab = "list" | "create" | "sign";

const CSR_TYPES = [
  { value: "appledev", label: "Apple Development" },
  ...CERT_TYPES,
];

export default function CSR() {
  const [tab, setTab] = createSignal<Tab>("list");
  const [csrs, { refetch }] = createResource<CsrListItem[]>(() => listCsrs());
  const [search, setSearch] = createSignal("");
  const [selected, setSelected] = createSignal<CsrListItem | null>(null);
  const [detail, setDetail] = createSignal<CreateCsrResult | null>(null);
  const [loadingDetail, setLoadingDetail] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [success, setSuccess] = createSignal<string | null>(null);
  const [copied, setCopied] = createSignal(false);

  // Create form
  const [cn, setCn] = createSignal("");
  const [csrType, setCsrType] = createSignal("webserver");
  const [email, setEmail] = createSignal("");
  const [creating, setCreating] = createSignal(false);
  const [createError, setCreateError] = createSignal<string | null>(null);
  const [createResult, setCreateResult] = createSignal<CreateCsrResult | null>(null);
  const [sanInput, setSanInput] = createSignal("");
  const [sans, setSans] = createSignal<string[]>([]);

  // Sign form
  const [signPem, setSignPem] = createSignal("");
  const [signType, setSignType] = createSignal("webserver");
  const [signCn, setSignCn] = createSignal("");
  const [signing, setSigning] = createSignal(false);
  const [signError, setSignError] = createSignal<string | null>(null);
  const [signResult, setSignResult] = createSignal<SignCsrResult | null>(null);
  const [decoded, setDecoded] = createSignal<DecodeCsrResult | null>(null);
  const [decoding, setDecoding] = createSignal(false);
  const [signSanInput, setSignSanInput] = createSignal("");
  const [signSans, setSignSans] = createSignal<string[]>([]);

  function selectRow(csr: CsrListItem) {
    setSelected(csr);
    setDetail(null);
    setError(null);
    setSuccess(null);
  }

  async function handleInfo() {
    const sel = selected();
    if (!sel?.cn) return;
    setLoadingDetail(true);
    setError(null);
    setDetail(null);
    try {
      const info = await getCsrInfo(sel.cn);
      setDetail(info);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoadingDetail(false);
    }
  }

  function copyPem() {
    const pem = detail()?.csr_pem ?? createResult()?.csr_pem;
    if (pem) {
      navigator.clipboard.writeText(pem);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }

  function addSan() {
    const value = sanInput().trim();
    if (value && !sans().includes(value)) {
      setSans([...sans(), value]);
      setSanInput("");
    }
  }

  function removeSan(index: number) {
    setSans(sans().filter((_, i) => i !== index));
  }

  async function handleCreate(e: Event) {
    e.preventDefault();
    const c = cn().trim();
    setCreateError(null);
    setCreateResult(null);

    if (!c) {
      setCreateError("Common Name is required.");
      return;
    }

    setCreating(true);
    try {
      const result = await createCsr({
        cn: c,
        csr_type: csrType(),
        email: email().trim() || undefined,
        alt_dns_names: sans().length > 0 ? sans() : undefined,
      });
      setCreateResult(result);
      setCn("");
      setEmail("");
      setSans([]);
      refetch();
    } catch (err) {
      setCreateError(String(err));
    } finally {
      setCreating(false);
    }
  }

  async function handleDecode() {
    const pem = signPem().trim();
    setSignError(null);
    setDecoded(null);

    if (!pem) {
      setSignError("CSR PEM is required.");
      return;
    }

    setDecoding(true);
    try {
      const result = await decodeCsr(pem);
      setDecoded(result);
      setSignCn(result.cn ?? "");
      setSignSans([...result.alt_dns_names]);
    } catch (err) {
      setSignError(String(err));
    } finally {
      setDecoding(false);
    }
  }

  function addSignSan() {
    const value = signSanInput().trim();
    if (value && !signSans().includes(value)) {
      setSignSans([...signSans(), value]);
      setSignSanInput("");
    }
  }

  function removeSignSan(index: number) {
    setSignSans(signSans().filter((_, i) => i !== index));
  }

  async function handleSign(e: Event) {
    e.preventDefault();
    const pem = signPem().trim();
    setSignError(null);
    setSignResult(null);

    if (!pem) {
      setSignError("CSR PEM is required.");
      return;
    }

    setSigning(true);
    try {
      const result = await signCsr({
        csr_pem: pem,
        csr_type: signType(),
        cn: signCn().trim() || undefined,
      });
      setSignResult(result);
      setSignPem("");
      setSignCn("");
    } catch (err) {
      setSignError(String(err));
    } finally {
      setSigning(false);
    }
  }

  const filteredCsrs = () => {
    const items = csrs() ?? [];
    const q = search().toLowerCase();
    if (!q) return items;
    return items.filter((c) =>
      [c.cn, c.csr_type, c.email, c.status, c.created_date].some((v) => v?.toLowerCase().includes(q))
    );
  };

  function statusClass(status: string | null): string {
    switch (status) {
      case "Pending": return "status-pending";
      case "Complete": return "status-complete";
      default: return "";
    }
  }

  return (
    <div class="page-csr">
      <div class="page-header">
        <h2>Certificate Signing Requests</h2>
        <Show when={tab() === "list"}>
          <div class="header-actions">
            <SearchInput value={search()} onInput={setSearch} />
            <button class="btn-ghost" onClick={() => refetch()} disabled={csrs.loading}>
              Refresh
            </button>
          </div>
        </Show>
      </div>

      <div class="tab-bar">
        <button
          class={`tab-btn ${tab() === "list" ? "tab-active" : ""}`}
          onClick={() => { setTab("list"); setError(null); setSuccess(null); }}
        >
          List
        </button>
        <button
          class={`tab-btn ${tab() === "create" ? "tab-active" : ""}`}
          onClick={() => { setTab("create"); setCreateError(null); setCreateResult(null); }}
        >
          Create
        </button>
        <button
          class={`tab-btn ${tab() === "sign" ? "tab-active" : ""}`}
          onClick={() => { setTab("sign"); setSignError(null); setSignResult(null); }}
        >
          Sign
        </button>
      </div>

      {/* ── List Tab ──────────────────────────────────────────────── */}
      <Show when={tab() === "list"}>
        <div class="tab-content">
          <Show when={csrs.loading}>
            <Spinner message="Loading CSRs..." />
          </Show>

          <Show when={csrs.error}>
            <p class="page-error">{String(csrs.error)}</p>
          </Show>

          <Show when={!csrs.loading && filteredCsrs().length === 0}>
            <p class="text-muted">No CSRs found.</p>
          </Show>

          <Show when={filteredCsrs().length > 0}>
            <div class="csr-table-wrap">
              <table class="csr-table">
                <thead>
                  <tr>
                    <th>Common Name</th>
                    <th>Type</th>
                    <th>Email</th>
                    <th>Status</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={filteredCsrs()}>
                    {(csr) => (
                      <tr
                        class={`csr-row ${selected()?.cn === csr.cn ? "csr-row-selected" : ""}`}
                        onClick={() => selectRow(csr)}
                      >
                        <td>{csr.cn ?? "\u2014"}</td>
                        <td>{csr.csr_type ?? "\u2014"}</td>
                        <td class="text-muted">{csr.email ?? "\u2014"}</td>
                        <td>
                          <span class={statusClass(csr.status)}>
                            {csr.status ?? "\u2014"}
                          </span>
                        </td>
                        <td class="mono">{csr.created_date ?? "\u2014"}</td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </Show>

          <Show when={selected()}>
            <div class="csr-actions">
              <button class="btn-secondary" onClick={handleInfo} disabled={loadingDetail()}>
                {loadingDetail() ? "Loading..." : "View CSR"}
              </button>
            </div>
          </Show>

          <Show when={error()}>
            <p class="page-error">{error()}</p>
          </Show>

          <Show when={success()}>
            <p class="page-success">{success()}</p>
          </Show>

          <Show when={loadingDetail()}>
            <Spinner message="Fetching CSR details..." />
          </Show>

          <Show when={detail()}>
            {(d) => (
              <div class="detail-section">
                <div class="detail-grid">
                  <Row label="Common Name" value={d().item.cn} />
                  <Row label="Type" value={d().item.csr_type} />
                  <Row label="Email" value={d().item.email} />
                  <Row label="Subject" value={d().item.subject} mono />
                  <Row label="Status" value={d().item.status} />
                  <Row label="Created" value={d().item.created_date} />
                </div>
                <Show when={d().csr_pem}>
                  <div class="pem-section">
                    <div class="pem-header">
                      <span class="detail-label">CSR PEM</span>
                      <button class="btn-ghost btn-sm" onClick={copyPem}>
                        {copied() ? "Copied" : "Copy"}
                      </button>
                    </div>
                    <pre class="pem-block mono">{d().csr_pem}</pre>
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
              <label class="form-label">Common Name</label>
              <input
                type="text"
                placeholder="e.g. mydevice.example.com"
                value={cn()}
                onInput={(e) => setCn(e.currentTarget.value)}
                autocomplete="off"
                autocorrect="off"
                autocapitalize="off"
                spellcheck={false}
              />
            </div>

            <div class="form-group">
              <label class="form-label">Certificate Type</label>
              <select value={csrType()} onChange={(e) => setCsrType(e.currentTarget.value)}>
                <For each={CSR_TYPES}>
                  {(t) => <option value={t.value}>{t.label}</option>}
                </For>
              </select>
            </div>

            <div class="form-group">
              <label class="form-label">Email (optional)</label>
              <input
                type="email"
                placeholder="e.g. admin@example.com"
                value={email()}
                onInput={(e) => setEmail(e.currentTarget.value)}
                autocomplete="off"
                autocorrect="off"
                autocapitalize="off"
                spellcheck={false}
              />
            </div>

            <div class="form-group">
              <label class="form-label">Subject Alternative Names</label>
              <div class="san-input-row">
                <input
                  type="text"
                  placeholder="e.g. alt.example.com"
                  value={sanInput()}
                  onInput={(e) => setSanInput(e.currentTarget.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") { e.preventDefault(); addSan(); }
                  }}
                  autocomplete="off"
                  autocorrect="off"
                  autocapitalize="off"
                  spellcheck={false}
                />
                <button type="button" class="btn-ghost" onClick={addSan}>Add</button>
              </div>
              <Show when={sans().length > 0}>
                <div class="san-list">
                  <For each={sans()}>
                    {(san, i) => (
                      <span class="san-tag">
                        {san}
                        <button type="button" class="san-remove" onClick={() => removeSan(i())}>
                          &times;
                        </button>
                      </span>
                    )}
                  </For>
                </div>
              </Show>
            </div>

            <Show when={createError()}>
              <p class="page-error">{createError()}</p>
            </Show>

            <Show when={createResult()}>
              {(r) => (
                <div class="create-success">
                  <p class="page-success">CSR created successfully.</p>
                  <div class="pem-section">
                    <div class="pem-header">
                      <span class="detail-label">CSR PEM</span>
                      <button type="button" class="btn-ghost btn-sm" onClick={copyPem}>
                        {copied() ? "Copied" : "Copy"}
                      </button>
                    </div>
                    <pre class="pem-block mono">{r().csr_pem}</pre>
                  </div>
                </div>
              )}
            </Show>

            <Show when={!createResult()}>
              <div class="form-actions">
                <button class="btn-primary" type="submit" disabled={creating() || !cn().trim()}>
                  {creating() ? "Creating..." : "Create CSR"}
                </button>
              </div>
            </Show>
          </form>
        </div>
      </Show>

      {/* ── Sign Tab ──────────────────────────────────────────────── */}
      <Show when={tab() === "sign"}>
        <div class="tab-content">
          <form class="create-form" onSubmit={handleSign}>
            <div class="form-group">
              <label class="form-label">CSR PEM</label>
              <textarea
                rows={10}
                placeholder="Paste CSR PEM here..."
                value={signPem()}
                onInput={(e) => {
                  setSignPem(e.currentTarget.value);
                  setDecoded(null);
                  setSignResult(null);
                  setSignError(null);
                }}
                autocomplete="off"
                autocorrect="off"
                autocapitalize="off"
                spellcheck={false}
              />
            </div>

            <Show when={!decoded() && !signResult()}>
              <div class="form-actions">
                <button
                  class="btn-primary"
                  type="button"
                  disabled={decoding() || !signPem().trim()}
                  onClick={handleDecode}
                >
                  {decoding() ? "Decoding..." : "Decode CSR"}
                </button>
              </div>
            </Show>

            <Show when={signError()}>
              <p class="page-error">{signError()}</p>
            </Show>

            <Show when={!signResult() ? decoded() : null}>
              {(d) => (
                <>
                  <div class="detail-grid mb-3">
                    <Row label="Subject" value={d().subject} mono />
                  </div>

                  <div class="form-group">
                    <label class="form-label">Common Name</label>
                    <input
                      type="text"
                      value={signCn()}
                      onInput={(e) => setSignCn(e.currentTarget.value)}
                      autocomplete="off"
                      autocorrect="off"
                      autocapitalize="off"
                      spellcheck={false}
                    />
                  </div>

                  <div class="form-group">
                    <label class="form-label">Certificate Type</label>
                    <select value={signType()} onChange={(e) => setSignType(e.currentTarget.value)}>
                      <For each={CSR_TYPES}>
                        {(t) => <option value={t.value}>{t.label}</option>}
                      </For>
                    </select>
                  </div>

                  <div class="form-group">
                    <label class="form-label">Subject Alternative Names</label>
                    <div class="san-input-row">
                      <input
                        type="text"
                        placeholder="e.g. alt.example.com"
                        value={signSanInput()}
                        onInput={(e) => setSignSanInput(e.currentTarget.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") { e.preventDefault(); addSignSan(); }
                        }}
                        autocomplete="off"
                        autocorrect="off"
                        autocapitalize="off"
                        spellcheck={false}
                      />
                      <button type="button" class="btn-ghost" onClick={addSignSan}>Add</button>
                    </div>
                    <Show when={signSans().length > 0}>
                      <div class="san-list">
                        <For each={signSans()}>
                          {(san, i) => (
                            <span class="san-tag">
                              {san}
                              <button type="button" class="san-remove" onClick={() => removeSignSan(i())}>
                                &times;
                              </button>
                            </span>
                          )}
                        </For>
                      </div>
                    </Show>
                    <Show when={signSans().length === 0}>
                      <p class="text-muted text-sm mt-1">No alternative names.</p>
                    </Show>
                  </div>

                  <div class="form-actions">
                    <button class="btn-primary" type="submit" disabled={signing()}>
                      {signing() ? "Signing..." : "Sign CSR"}
                    </button>
                  </div>
                </>
              )}
            </Show>

            <Show when={signResult()}>
              {(r) => (
                <div class="create-success">
                  <p class="page-success">
                    Certificate signed successfully (serial {r().cert.serial}).
                  </p>
                  <div class="pem-section">
                    <div class="pem-header">
                      <span class="detail-label">Certificate PEM</span>
                      <button
                        type="button"
                        class="btn-ghost btn-sm"
                        onClick={() => {
                          navigator.clipboard.writeText(r().cert_pem);
                          setCopied(true);
                          setTimeout(() => setCopied(false), 2000);
                        }}
                      >
                        {copied() ? "Copied" : "Copy"}
                      </button>
                    </div>
                    <pre class="pem-block mono">{r().cert_pem}</pre>
                  </div>
                </div>
              )}
            </Show>
          </form>
        </div>
      </Show>

      <style>{`
        .page-csr {
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

        .csr-table-wrap {
          border: 1px solid var(--border);
          border-radius: 10px;
          overflow: auto;
          max-height: 300px;
        }

        .csr-table {
          width: 100%;
          border-collapse: collapse;
          font-size: 0.875rem;
        }

        .csr-table th {
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

        .csr-table td {
          padding: 10px 14px;
          border-bottom: 1px solid var(--border);
          color: var(--text-primary);
        }

        .csr-row {
          cursor: pointer;
          transition: background 0.1s;
        }

        .csr-row:hover {
          background: var(--bg-elevated);
        }

        .csr-row-selected {
          background: var(--accent-glow) !important;
        }

        .csr-row:last-child td {
          border-bottom: none;
        }

        .csr-actions {
          display: flex;
          align-items: center;
          gap: 8px;
          margin-top: 16px;
        }

        .status-pending {
          color: var(--warning, #f5a623);
        }

        .status-complete {
          color: var(--success);
        }

        .detail-section {
          margin-top: 16px;
        }

        .detail-grid {
          display: grid;
          gap: 8px;
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

        .pem-section {
          margin-top: 16px;
        }

        .pem-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 4px;
        }

        .pem-block {
          padding: 12px;
          background: var(--bg-surface);
          border: 1px solid var(--border);
          border-radius: 6px;
          font-size: 0.6875rem;
          line-height: 1.5;
          white-space: pre-wrap;
          word-break: break-all;
          max-height: 200px;
          overflow: auto;
        }

        .create-form {
          max-width: 520px;
          display: flex;
          flex-direction: column;
          gap: 16px;
        }

        .create-form textarea {
          font-family: var(--font-mono, monospace);
          font-size: 0.75rem;
          resize: vertical;
        }

        .form-group {
          display: flex;
          flex-direction: column;
          gap: 6px;
        }

        .san-input-row {
          display: flex;
          gap: 8px;
        }

        .san-input-row input {
          flex: 1;
        }

        .san-list {
          display: flex;
          flex-wrap: wrap;
          gap: 6px;
          margin-top: 8px;
        }

        .san-tag {
          display: inline-flex;
          align-items: center;
          gap: 4px;
          padding: 4px 10px;
          background: var(--bg-elevated);
          border: 1px solid var(--border);
          border-radius: 6px;
          font-size: 0.8125rem;
          color: var(--text-primary);
        }

        .san-remove {
          background: none;
          border: none;
          color: var(--text-secondary);
          cursor: pointer;
          font-size: 1rem;
          padding: 0 2px;
          line-height: 1;
        }

        .san-remove:hover {
          color: var(--error);
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
