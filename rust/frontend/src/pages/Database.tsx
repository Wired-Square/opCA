import { Show, For, createSignal, createResource } from "solid-js";
import { getDatabaseInfo, getActionLog } from "../api/database";
import { uploadCaDatabase } from "../api/ca";
import Spinner from "../components/Spinner";
import SearchInput from "../components/SearchInput";
import type { DatabaseInfo, LogEntry } from "../api/types";

type Tab = "log" | "statistics" | "config";

export default function Database() {
  const [tab, setTab] = createSignal<Tab>("log");
  const [info, { refetch }] = createResource<DatabaseInfo>(getDatabaseInfo);
  const [log, { refetch: refetchLog }] = createResource<LogEntry[]>(getActionLog);
  const [logSearch, setLogSearch] = createSignal("");
  const [uploading, setUploading] = createSignal(false);
  const [uploadResult, setUploadResult] = createSignal<string | null>(null);

  const filteredLog = () => {
    const items = log() ?? [];
    const q = logSearch().toLowerCase();
    if (!q) return items;
    return items.filter((e) =>
      [e.action, e.detail, formatLogTime(e.timestamp)].some((v) => v?.toLowerCase().includes(q))
    );
  };

  const hasPrivateStore = () => !!info()?.config.ca_private_store;

  function refresh() {
    refetch();
    refetchLog();
  }

  async function handleUpload() {
    setUploading(true);
    setUploadResult(null);
    try {
      await uploadCaDatabase();
      setUploadResult("ok");
      refetchLog();
      setTimeout(() => setUploadResult(null), 3000);
    } catch (e) {
      setUploadResult(String(e));
      refetchLog();
    } finally {
      setUploading(false);
    }
  }

  return (
    <div class="page-database">
      <div class="page-header">
        <h2>Database</h2>
        <div class="header-actions">
          <Show when={tab() === "log"}>
            <SearchInput value={logSearch()} onInput={setLogSearch} />
          </Show>
          <button class="btn-ghost" onClick={refresh} disabled={info.loading}>
            {info.loading ? "Loading\u2026" : "Refresh"}
          </button>
          <Show when={hasPrivateStore()}>
            <button class="btn-ghost" onClick={handleUpload} disabled={uploading()}>
              {uploading() ? "Uploading\u2026" : "Upload Database"}
            </button>
          </Show>
        </div>
      </div>

      <Show when={uploadResult() === "ok"}>
        <p class="upload-success">Database uploaded to private store.</p>
      </Show>
      <Show when={uploadResult() && uploadResult() !== "ok"}>
        <p class="page-error">{uploadResult()}</p>
      </Show>

      <div class="tab-bar">
        <button
          class={`tab-btn ${tab() === "log" ? "tab-active" : ""}`}
          onClick={() => setTab("log")}
        >Activity Log</button>
        <button
          class={`tab-btn ${tab() === "statistics" ? "tab-active" : ""}`}
          onClick={() => setTab("statistics")}
        >Statistics</button>
        <button
          class={`tab-btn ${tab() === "config" ? "tab-active" : ""}`}
          onClick={() => setTab("config")}
        >Configuration</button>
      </div>

      <div class="tab-content">
        <Show when={tab() === "log"}>
          <LogTab entries={filteredLog} loading={log.loading} />
        </Show>
        <Show when={tab() === "statistics"}>
          <StatisticsTab info={info} />
        </Show>
        <Show when={tab() === "config"}>
          <ConfigTab info={info} />
        </Show>
      </div>

      <style>{dbStyles}</style>
    </div>
  );
}

function LogTab(props: { entries: () => LogEntry[]; loading: boolean }) {
  return (
    <Show when={!props.loading} fallback={<Spinner message="Loading…" />}>
      <Show when={props.entries().length > 0} fallback={<p class="text-muted">No activity recorded yet.</p>}>
        <div class="log-list">
          <For each={[...props.entries()].reverse()}>
            {(entry) => (
              <div class={`log-entry ${entry.success ? "" : "log-error"}`}>
                <span class="log-time">{formatLogTime(entry.timestamp)}</span>
                <span class={`log-status ${entry.success ? "log-ok" : "log-fail"}`}>
                  {entry.success ? "\u2713" : "\u2717"}
                </span>
                <span class="log-action">{entry.action}</span>
                <Show when={entry.detail}>
                  <span class="log-detail">{entry.detail}</span>
                </Show>
              </div>
            )}
          </For>
        </div>
      </Show>
    </Show>
  );
}

function StatisticsTab(props: { info: any }) {
  return (
    <>
      <Show when={props.info.error}>
        <p class="page-error">{String(props.info.error)}</p>
      </Show>

      <Show when={props.info()} fallback={<Spinner message="Loading…" />}>
        {(d) => (
          <div class="detail-grid">
            <Row label="Schema Version" value={String(d().schema_version)} />
            <Row label="Total Certificates" value={String(d().total_certs)} />
            <Row label="External Certificates" value={String(d().total_external_certs)} />
          </div>
        )}
      </Show>
    </>
  );
}

function ConfigTab(props: { info: any }) {
  return (
    <>
      <Show when={props.info.error}>
        <p class="page-error">{String(props.info.error)}</p>
      </Show>

      <Show when={props.info()} fallback={<Spinner message="Loading…" />}>
        {(d) => (
          <div class="detail-grid">
            <Row label="Next Serial" value={d().config.next_serial != null ? String(d().config.next_serial) : null} />
            <Row label="Next CRL Serial" value={d().config.next_crl_serial != null ? String(d().config.next_crl_serial) : null} />
            <Row label="Organisation" value={d().config.org} />
            <Row label="Organisational Unit" value={d().config.ou} />
            <Row label="Email" value={d().config.email} />
            <Row label="City" value={d().config.city} />
            <Row label="State" value={d().config.state} />
            <Row label="Country" value={d().config.country} />
            <Row label="Certificate Days" value={d().config.days != null ? String(d().config.days) : null} />
            <Row label="CRL Days" value={d().config.crl_days != null ? String(d().config.crl_days) : null} />
            <Row label="CA URL" value={d().config.ca_url} mono />
            <Row label="CRL URL" value={d().config.crl_url} mono />
            <Row label="Public Store" value={d().config.ca_public_store} mono />
            <Row label="Private Store" value={d().config.ca_private_store} mono />
            <Row label="Backup Store" value={d().config.ca_backup_store} mono />
          </div>
        )}
      </Show>
    </>
  );
}

function formatLogTime(timestamp: number): string {
  const d = new Date(timestamp * 1000);
  return d.toLocaleTimeString("en-AU", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
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

const dbStyles = `
  .page-database {
    padding: 32px;
    display: flex;
    flex-direction: column;
    height: 100%;
    box-sizing: border-box;
  }

  .page-database h2 {
    margin: 0;
  }

  .page-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 20px;
    flex-shrink: 0;
  }

  .header-actions {
    display: flex;
    gap: 8px;
  }

  .upload-success {
    color: #22c55e;
    font-size: 0.875rem;
    padding: 8px 12px;
    background: rgba(34, 197, 94, 0.1);
    border-radius: 6px;
    margin-bottom: 16px;
  }

  .page-error {
    color: var(--error);
    font-size: 0.875rem;
    padding: 8px 12px;
    background: rgba(255, 69, 58, 0.1);
    border-radius: 6px;
    margin-bottom: 16px;
  }

  .section-heading {
    margin-top: 32px;
    margin-bottom: 16px;
    font-size: 1rem;
    color: var(--text-secondary);
    font-weight: 600;
  }

  .section-heading:first-child {
    margin-top: 0;
  }

  .detail-grid {
    display: grid;
    gap: 12px;
  }

  .detail-row {
    display: flex;
    gap: 16px;
    padding: 8px 12px;
    border-radius: 6px;
  }

  .detail-row:nth-child(odd) {
    background: var(--bg-elevated);
  }

  .detail-label {
    min-width: 180px;
    font-size: 0.8125rem;
    font-weight: 500;
    color: var(--text-secondary);
  }

  .detail-value {
    font-size: 0.875rem;
    color: var(--text-primary);
    word-break: break-all;
  }

  .log-list {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .log-entry {
    display: flex;
    align-items: baseline;
    gap: 10px;
    padding: 6px 12px;
    border-radius: 6px;
    font-size: 0.8125rem;
  }

  .log-entry:nth-child(odd) {
    background: var(--bg-elevated);
  }

  .log-entry.log-error {
    background: rgba(255, 69, 58, 0.06);
  }

  .log-time {
    font-family: "SF Mono", "Cascadia Code", "Fira Code", monospace;
    font-size: 0.75rem;
    color: var(--text-tertiary);
    flex-shrink: 0;
  }

  .log-status {
    flex-shrink: 0;
    font-weight: 700;
    width: 16px;
    text-align: center;
  }

  .log-ok {
    color: #22c55e;
  }

  .log-fail {
    color: #ef4444;
  }

  .log-action {
    font-weight: 600;
    color: var(--text-primary);
    flex-shrink: 0;
  }

  .log-detail {
    color: var(--text-secondary);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    min-width: 0;
  }
`;
