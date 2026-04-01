import { Show, For, createSignal, createResource, type Resource } from "solid-js";
import { getDatabaseInfo, getActionLog } from "../api/database";
import { uploadCaDatabase } from "../api/ca";
import Spinner from "../components/Spinner";
import SearchInput from "../components/SearchInput";
import type { DatabaseInfo, LogEntry } from "../api/types";
import "../styles/pages/database.css";

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

function StatisticsTab(props: { info: Resource<DatabaseInfo> }) {
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

function ConfigTab(props: { info: Resource<DatabaseInfo> }) {
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

