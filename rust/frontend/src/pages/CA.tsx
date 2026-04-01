import { Show, For, createSignal, createResource, onMount, onCleanup } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { appState, setAppState, hasCA, type VaultState } from "../stores/app";
import { getCaInfo, getCaConfig, updateCaConfig, initCa, testStores, uploadCaCert, resignCa } from "../api/ca";
import { vaultRestore, vaultInfo } from "../api/vault-backup";
import { formatDate } from "../utils/dates";
import TzToggle from "../components/TzToggle";
import Spinner from "../components/Spinner";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import type { CaInfo, CaConfig, RestoreResult, BackupInfoResult, StoreTestResults } from "../api/types";

type Tab = "certificate" | "config" | "stores" | "init" | "restore" | "info";

export default function CA() {
  const [tab, setTab] = createSignal<Tab>(hasCA() ? "certificate" : "init");
  const [caInfo, { refetch: refetchCaInfo }] = createResource<CaInfo>(getCaInfo);
  const [caConfig, { refetch: refetchConfig }] = createResource<CaConfig>(getCaConfig);

  return (
    <div class="page-ca">
      <h2>Certificate Authority</h2>

      <div class="tab-bar">
        <Show when={hasCA()}>
          <button
            class={`tab-btn ${tab() === "certificate" ? "tab-active" : ""}`}
            onClick={() => setTab("certificate")}
          >Certificate</button>
          <button
            class={`tab-btn ${tab() === "config" ? "tab-active" : ""}`}
            onClick={() => setTab("config")}
          >Configuration</button>
          <button
            class={`tab-btn ${tab() === "stores" ? "tab-active" : ""}`}
            onClick={() => setTab("stores")}
          >Stores</button>
        </Show>
        <Show when={!hasCA()}>
          <button
            class={`tab-btn ${tab() === "init" ? "tab-active" : ""}`}
            onClick={() => setTab("init")}
          >Initialise CA</button>
          <button
            class={`tab-btn ${tab() === "restore" ? "tab-active" : ""}`}
            onClick={() => setTab("restore")}
          >Restore</button>
          <button
            class={`tab-btn ${tab() === "info" ? "tab-active" : ""}`}
            onClick={() => setTab("info")}
          >Info</button>
        </Show>
      </div>

      <Show when={tab() === "certificate"}>
        <CertificateTab info={caInfo} config={caConfig} onResign={refetchCaInfo} />
      </Show>
      <Show when={tab() === "config"}>
        <ConfigTab config={caConfig} onSave={refetchConfig} />
      </Show>
      <Show when={tab() === "stores"}>
        <StoresTab config={caConfig} onSave={refetchConfig} />
      </Show>
      <Show when={tab() === "init"}>
        <InitTab />
      </Show>
      <Show when={tab() === "restore"}>
        <RestoreTab />
      </Show>
      <Show when={tab() === "info"}>
        <InfoTab />
      </Show>

      <style>{caStyles}</style>
    </div>
  );
}

function CertificateTab(props: {
  info: () => CaInfo | undefined;
  config: () => CaConfig | undefined;
  onResign: () => void;
}) {
  const [copied, setCopied] = createSignal(false);
  const [uploading, setUploading] = createSignal(false);
  const [uploadResult, setUploadResult] = createSignal<string | null>(null);
  const [showResign, setShowResign] = createSignal(false);
  const [resignDays, setResignDays] = createSignal("3650");
  const [resigning, setResigning] = createSignal(false);
  const [resignResult, setResignResult] = createSignal<string | null>(null);

  const hasPublicStore = () => !!props.config()?.ca_public_store;

  function copyPem() {
    const pem = props.info()?.cert_pem;
    if (pem) {
      navigator.clipboard.writeText(pem);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }

  async function handleUpload() {
    setUploading(true);
    setUploadResult(null);
    try {
      await uploadCaCert();
      setUploadResult("ok");
      setTimeout(() => setUploadResult(null), 3000);
    } catch (e) {
      setUploadResult(String(e));
    } finally {
      setUploading(false);
    }
  }

  async function handleResign() {
    const days = parseInt(resignDays());
    if (!days || days <= 0) {
      setResignResult("Please enter a valid number of days.");
      return;
    }
    setResigning(true);
    setResignResult(null);
    try {
      await resignCa(days);
      setResignResult("ok");
      setShowResign(false);
      props.onResign();
      setTimeout(() => setResignResult(null), 5000);
    } catch (e) {
      setResignResult(String(e));
    } finally {
      setResigning(false);
    }
  }

  return (
    <div class="tab-content">
      <Show when={props.info()} fallback={<Spinner message="Loading…" />}>
        {(info) => (
          <>
            <div class="detail-grid">
              <DetailRow label="Common Name" value={info().cn} />
              <DetailRow label="Subject" value={info().subject} mono />
              <DetailRow label="Issuer" value={info().issuer} mono />
              <DetailRow label="Serial" value={info().serial} mono />
              <DetailRow label={<>Valid From <TzToggle /></>} value={formatDate(info().not_before)} />
              <DetailRow label="Valid Until" value={formatDate(info().not_after)} />
              <DetailRow label="Key Type" value={info().key_type} />
              <DetailRow label="Key Size" value={info().key_size} />
              <div class="detail-row">
                <span class="detail-label">Status</span>
                <span class={`status-badge ${info().is_valid ? "status-valid" : "status-invalid"}`}>
                  {info().is_valid ? "Valid" : "Invalid"}
                </span>
              </div>
            </div>

            <div class="form-actions">
              <button class="btn-secondary" onClick={() => setShowResign(!showResign())}>
                {showResign() ? "Cancel" : "Re-sign Certificate"}
              </button>
              <Show when={hasPublicStore()}>
                <button class="btn-warning" onClick={handleUpload} disabled={uploading()}>
                  {uploading() ? "Uploading…" : "Upload Certificate"}
                </button>
              </Show>
            </div>

            <Show when={resignResult() === "ok"}>
              <p class="form-success">CA certificate re-signed successfully.</p>
            </Show>

            <Show when={showResign()}>
              <div class="resign-section">
                <p class="text-muted">
                  Re-sign the CA certificate with the same key pair but new validity dates.
                  Existing certificates remain valid.
                </p>
                <div class="resign-form">
                  <div class="form-group">
                    <label class="form-label">New validity (days)</label>
                    <input
                      type="number"
                      value={resignDays()}
                      onInput={(e) => setResignDays(e.currentTarget.value)}
                      min="1"
                      class="max-w-input"
                    />
                  </div>
                  <div class="form-actions">
                    <button class="btn-primary" onClick={handleResign} disabled={resigning()}>
                      {resigning() ? "Re-signing…" : "Re-sign CA"}
                    </button>
                  </div>
                </div>
                <Show when={resignResult() && resignResult() !== "ok"}>
                  <p class="form-error">{resignResult()}</p>
                </Show>
              </div>
            </Show>

            <Show when={hasPublicStore()}>
              <Show when={uploadResult() === "ok"}>
                <p class="form-success">Certificate uploaded to public store.</p>
              </Show>
              <Show when={uploadResult() && uploadResult() !== "ok"}>
                <p class="form-error">{uploadResult()}</p>
              </Show>
            </Show>

            <Show when={info().cert_pem}>
              <div class="pem-section">
                <div class="pem-header">
                  <span class="pem-label">Certificate PEM</span>
                  <button class="btn-ghost btn-sm" onClick={copyPem}>
                    {copied() ? "Copied" : "Copy"}
                  </button>
                </div>
                <pre class="pem-block">{info().cert_pem}</pre>
              </div>
            </Show>
          </>
        )}
      </Show>
    </div>
  );
}

function ConfigTab(props: { config: () => CaConfig | undefined; onSave: () => void }) {
  const [saving, setSaving] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [form, setForm] = createSignal<Partial<CaConfig>>({});

  const merged = () => ({ ...props.config(), ...form() } as CaConfig);
  const set = (key: keyof CaConfig, value: string | number | null) =>
    setForm((f) => ({ ...f, [key]: value || null }));

  async function handleSave() {
    setSaving(true);
    setError(null);
    try {
      await updateCaConfig(merged());
      setForm({});
      props.onSave();
    } catch (e) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div class="tab-content">
      <Show when={props.config()} fallback={<Spinner message="Loading…" />}>
        {(_) => (
          <div class="config-form">
            <div class="form-grid">
              <FormField label="Organisation" value={merged().org} onChange={(v) => set("org", v)} />
              <FormField label="Organisational Unit" value={merged().ou} onChange={(v) => set("ou", v)} />
              <FormField label="Email" value={merged().email} onChange={(v) => set("email", v)} />
              <FormField label="City" value={merged().city} onChange={(v) => set("city", v)} />
              <FormField label="State" value={merged().state} onChange={(v) => set("state", v)} />
              <FormField label="Country" value={merged().country} onChange={(v) => set("country", v)} />
              <FormField label="Certificate Days" value={String(merged().days ?? "")}
                onChange={(v) => set("days", v ? parseInt(v) : null)} type="number" />
              <FormField label="CRL Days" value={String(merged().crl_days ?? "")}
                onChange={(v) => set("crl_days", v ? parseInt(v) : null)} type="number" />
              <FormField label="CA URL" value={merged().ca_url} onChange={(v) => set("ca_url", v)} />
              <FormField label="CRL URL" value={merged().crl_url} onChange={(v) => set("crl_url", v)} />
            </div>

            <Show when={error()}>
              <p class="form-error">{error()}</p>
            </Show>

            <div class="form-actions">
              <button class="btn-primary" onClick={handleSave} disabled={saving()}>
                {saving() ? "Saving…" : "Save Configuration"}
              </button>
            </div>
          </div>
        )}
      </Show>
    </div>
  );
}

function StoresTab(props: { config: () => CaConfig | undefined; onSave: () => void }) {
  const [saving, setSaving] = createSignal(false);
  const [testing, setTesting] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [testResults, setTestResults] = createSignal<StoreTestResults | null>(null);
  const [testError, setTestError] = createSignal<string | null>(null);
  const [form, setForm] = createSignal<Partial<CaConfig>>({});

  const merged = () => ({ ...props.config(), ...form() } as CaConfig);
  const set = (key: keyof CaConfig, value: string | null) =>
    setForm((f) => ({ ...f, [key]: value || null }));

  async function handleSave() {
    setSaving(true);
    setError(null);
    try {
      await updateCaConfig(merged());
      setForm({});
      props.onSave();
    } catch (e) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  }

  async function handleTest() {
    setTesting(true);
    setTestResults(null);
    setTestError(null);
    try {
      const results = await testStores();
      setTestResults(results);
    } catch (e) {
      setTestError(String(e));
    } finally {
      setTesting(false);
    }
  }

  return (
    <div class="tab-content">
      <Show when={props.config()} fallback={<Spinner message="Loading…" />}>
        {(_) => (
          <div class="config-form">
            <div class="form-grid">
              <FormField label="Public Store" value={merged().ca_public_store}
                onChange={(v) => set("ca_public_store", v)} />
              <FormField label="Private Store" value={merged().ca_private_store}
                onChange={(v) => set("ca_private_store", v)} />
              <FormField label="Backup Store" value={merged().ca_backup_store}
                onChange={(v) => set("ca_backup_store", v)} />
            </div>

            <Show when={error()}>
              <p class="form-error">{error()}</p>
            </Show>

            <div class="form-actions">
              <button class="btn-primary" onClick={handleSave} disabled={saving()}>
                {saving() ? "Saving…" : "Save Stores"}
              </button>
              <button class="btn-ghost" onClick={handleTest} disabled={testing()}>
                {testing() ? "Testing…" : "Test Stores"}
              </button>
            </div>

            <Show when={testing()}>
              <Spinner message="Testing store connections…" />
            </Show>

            <Show when={testError()}>
              <p class="form-error">{testError()}</p>
            </Show>

            <Show when={testResults()}>
              {(results) => (
                <div class="store-test-results">
                  <For each={Object.entries(results())}>
                    {([name, status]) => (
                      <div class={`store-test-row ${status === "ok" ? "test-pass" : "test-fail"}`}>
                        <span class="store-test-name">{name}</span>
                        <span class="store-test-status">
                          {status === "ok" ? "Connected" : status}
                        </span>
                      </div>
                    )}
                  </For>
                </div>
              )}
            </Show>
          </div>
        )}
      </Show>
    </div>
  );
}

function InitTab() {
  const [saving, setSaving] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [form, setForm] = createSignal<Partial<CaConfig>>({
    days: 3650,
    crl_days: 30,
  });

  const set = (key: keyof CaConfig, value: string | number | null) =>
    setForm((f) => ({ ...f, [key]: value || null }));

  async function handleInit() {
    setSaving(true);
    setError(null);
    try {
      await initCa(form() as CaConfig);
      window.location.reload();
    } catch (e) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div class="tab-content">
      <p class="text-muted mb-3">
        No Certificate Authority found. Fill in the details below to initialise one.
      </p>
      <div class="config-form">
        <div class="form-grid">
          <FormField label="Organisation" value={form().org} onChange={(v) => set("org", v)} />
          <FormField label="Organisational Unit" value={form().ou} onChange={(v) => set("ou", v)} />
          <FormField label="Email" value={form().email} onChange={(v) => set("email", v)} />
          <FormField label="City" value={form().city} onChange={(v) => set("city", v)} />
          <FormField label="State" value={form().state} onChange={(v) => set("state", v)} />
          <FormField label="Country" value={form().country} onChange={(v) => set("country", v)} />
          <FormField label="Certificate Days" value={String(form().days ?? "")}
            onChange={(v) => set("days", v ? parseInt(v) : null)} type="number" />
          <FormField label="CRL Days" value={String(form().crl_days ?? "")}
            onChange={(v) => set("crl_days", v ? parseInt(v) : null)} type="number" />
          <FormField label="CA URL" value={form().ca_url} onChange={(v) => set("ca_url", v)} />
          <FormField label="CRL URL" value={form().crl_url} onChange={(v) => set("crl_url", v)} />
        </div>

        <Show when={error()}>
          <p class="form-error">{error()}</p>
        </Show>

        <div class="form-actions">
          <button class="btn-primary" onClick={handleInit} disabled={saving()}>
            {saving() ? "Initialising…" : "Initialise CA"}
          </button>
        </div>
      </div>
    </div>
  );
}

function RestoreTab() {
  const navigate = useNavigate();
  const [restorePath, setRestorePath] = createSignal("");
  const [restorePassword, setRestorePassword] = createSignal("");
  const [restoring, setRestoring] = createSignal(false);
  const [restoreResult, setRestoreResult] = createSignal<RestoreResult | null>(null);
  const [restoreError, setRestoreError] = createSignal<string | null>(null);
  const [progressMsg, setProgressMsg] = createSignal<string | null>(null);
  let unlistenProgress: UnlistenFn | undefined;

  onMount(async () => {
    unlistenProgress = await listen<string>("vault-progress", (event) => {
      setProgressMsg(event.payload);
    });
  });

  onCleanup(() => {
    unlistenProgress?.();
  });

  async function browseOpen() {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const path = await open({
      defaultPath: restorePath() || undefined,
      multiple: false,
      filters: [{ name: "opCA Backup", extensions: ["opca"] }],
    });
    if (path) setRestorePath(path as string);
  }

  async function handleRestore() {
    setRestoreError(null);
    setRestoreResult(null);

    const path = restorePath().trim();
    if (!path) {
      setRestoreError("Please specify a backup file.");
      return;
    }
    if (!restorePassword()) {
      setRestoreError("Please enter the backup password.");
      return;
    }

    setRestoring(true);
    setProgressMsg(null);
    try {
      const result = await vaultRestore(path, restorePassword(), appState.vault, appState.account);
      setProgressMsg(null);
      setRestoreResult(result);
      setRestorePassword("");

      // Re-check vault state after restore
      const newState = await invoke<string>("check_vault_state");
      setAppState("vaultState", newState as VaultState);

      setTimeout(() => navigate("/dashboard"), 1500);
    } catch (e) {
      setRestoreError(String(e));
    } finally {
      setRestoring(false);
      setProgressMsg(null);
    }
  }

  return (
    <div class="tab-content">
      <p class="text-muted mb-3">
        Restore a vault from an encrypted backup file.
      </p>
      <div class="config-form">
        <div class="form-group">
          <label class="form-label">Backup file</label>
          <div class="file-row">
            <input
              type="text"
              placeholder="e.g. /tmp/my-vault.opca"
              value={restorePath()}
              onInput={(e) => setRestorePath(e.currentTarget.value)}
              autocomplete="off"
              autocorrect="off"
              autocapitalize="off"
              spellcheck={false}
            />
            <button class="btn-ghost" onClick={browseOpen}>Browse</button>
          </div>
        </div>

        <div class="form-group">
          <label class="form-label">Password</label>
          <input
            type="password"
            placeholder="Decryption password"
            value={restorePassword()}
            onInput={(e) => setRestorePassword(e.currentTarget.value)}
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            spellcheck={false}
          />
        </div>

        <Show when={restoreError()}>
          <p class="form-error">{restoreError()}</p>
        </Show>

        <div class="form-actions">
          <button class="btn-primary" onClick={handleRestore} disabled={restoring()}>
            {restoring() ? "Restoring…" : "Restore"}
          </button>
        </div>

        <Show when={restoring() && progressMsg()}>
          <Spinner message={progressMsg()!} />
        </Show>

        <Show when={restoreResult()}>
          {(r) => (
            <div class="restore-result">
              <p class="form-success">
                Restore complete — {r().items_restored} item{r().items_restored !== 1 ? "s" : ""} restored.
              </p>
              <Show when={r().item_breakdown.length > 0}>
                <div class="detail-grid">
                  <For each={r().item_breakdown}>
                    {(entry) => (
                      <DetailRow label={entry.item_type} value={String(entry.count)} />
                    )}
                  </For>
                </div>
              </Show>
            </div>
          )}
        </Show>
      </div>
    </div>
  );
}

function InfoTab() {
  const [infoPath, setInfoPath] = createSignal("");
  const [infoPassword, setInfoPassword] = createSignal("");
  const [loadingInfo, setLoadingInfo] = createSignal(false);
  const [infoResult, setInfoResult] = createSignal<BackupInfoResult | null>(null);
  const [infoError, setInfoError] = createSignal<string | null>(null);

  async function browseOpen() {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const path = await open({
      defaultPath: infoPath() || undefined,
      multiple: false,
      filters: [{ name: "opCA Backup", extensions: ["opca"] }],
    });
    if (path) setInfoPath(path as string);
  }

  async function handleInfo() {
    setInfoError(null);
    setInfoResult(null);

    const path = infoPath().trim();
    if (!path) {
      setInfoError("Please specify a backup file.");
      return;
    }
    if (!infoPassword()) {
      setInfoError("Please enter the backup password.");
      return;
    }

    setLoadingInfo(true);
    try {
      const result = await vaultInfo(path, infoPassword());
      setInfoResult(result);
      setInfoPassword("");
    } catch (e) {
      setInfoError(String(e));
    } finally {
      setLoadingInfo(false);
    }
  }

  return (
    <div class="tab-content">
      <p class="text-muted mb-3">
        View the contents of an encrypted backup file without restoring it.
      </p>
      <div class="config-form">
        <div class="form-group">
          <label class="form-label">Backup file</label>
          <div class="file-row">
            <input
              type="text"
              placeholder="e.g. /tmp/my-vault.opca"
              value={infoPath()}
              onInput={(e) => setInfoPath(e.currentTarget.value)}
              autocomplete="off"
              autocorrect="off"
              autocapitalize="off"
              spellcheck={false}
            />
            <button class="btn-ghost" onClick={browseOpen}>Browse</button>
          </div>
        </div>

        <div class="form-group">
          <label class="form-label">Password</label>
          <input
            type="password"
            placeholder="Decryption password"
            value={infoPassword()}
            onInput={(e) => setInfoPassword(e.currentTarget.value)}
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            spellcheck={false}
          />
        </div>

        <Show when={infoError()}>
          <p class="form-error">{infoError()}</p>
        </Show>

        <div class="form-actions">
          <button class="btn-primary" onClick={handleInfo} disabled={loadingInfo()}>
            {loadingInfo() ? "Reading…" : "Show Info"}
          </button>
        </div>

        <Show when={loadingInfo()}>
          <Spinner message="Decrypting backup…" />
        </Show>

        <Show when={infoResult()}>
          {(r) => (
            <div class="restore-result">
              <div class="detail-grid">
                <DetailRow label="opCA Version" value={r().opca_version} />
                <DetailRow label="Vault Name" value={r().vault_name} />
                <DetailRow label="Backup Date" value={r().backup_date} />
                <DetailRow label="Item Count" value={String(r().item_count)} />
              </div>

              <Show when={r().item_breakdown.length > 0}>
                <h3 class="section-heading">Item Breakdown</h3>
                <div class="detail-grid">
                  <For each={r().item_breakdown}>
                    {(entry) => (
                      <DetailRow label={entry.item_type} value={String(entry.count)} />
                    )}
                  </For>
                </div>
              </Show>
            </div>
          )}
        </Show>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Shared sub-components
// ---------------------------------------------------------------------------

function DetailRow(props: {
  label: string | import("solid-js").JSX.Element;
  value: string | null | undefined;
  mono?: boolean;
  valueClass?: string;
}) {
  return (
    <div class="detail-row">
      <span class="detail-label">{props.label}</span>
      <span class={`detail-value ${props.mono ? "mono" : ""} ${props.valueClass ?? ""}`}>
        {props.value ?? "\u2014"}
      </span>
    </div>
  );
}

function FormField(props: {
  label: string;
  value: string | null | undefined;
  onChange: (value: string) => void;
  type?: string;
}) {
  return (
    <div class="form-group">
      <label class="form-label">{props.label}</label>
      <input
        type={props.type ?? "text"}
        value={props.value ?? ""}
        onInput={(e) => props.onChange(e.currentTarget.value)}
        autocomplete="off"
        autocorrect="off"
        autocapitalize="off"
        spellcheck={false}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const caStyles = `
  .page-ca {
    padding: 32px;
    display: flex;
    flex-direction: column;
    height: 100%;
    box-sizing: border-box;
  }

  .page-ca h2 {
    margin: 0 0 20px;
    flex-shrink: 0;
  }

  .status-badge {
    display: inline-block;
    padding: 4px 14px;
    font-size: 0.8125rem;
    font-weight: 600;
    border-radius: 20px;
    letter-spacing: 0.02em;
  }

  .status-valid {
    color: #22c55e;
    background: rgba(34, 197, 94, 0.12);
    border: 1px solid rgba(34, 197, 94, 0.3);
  }

  .status-invalid {
    color: #ef4444;
    background: rgba(239, 68, 68, 0.12);
    border: 1px solid rgba(239, 68, 68, 0.3);
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
    min-width: 140px;
    font-size: 0.8125rem;
    font-weight: 500;
    color: var(--text-secondary);
  }

  .detail-value {
    font-size: 0.875rem;
    color: var(--text-primary);
    word-break: break-all;
  }

  .pem-section {
    margin-top: 24px;
  }

  .pem-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 8px;
  }

  .pem-label {
    font-size: 0.8125rem;
    font-weight: 500;
    color: var(--text-secondary);
  }

  .pem-block {
    padding: 16px;
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    border-radius: 8px;
    font-family: "SF Mono", "Cascadia Code", "Fira Code", monospace;
    font-size: 0.75rem;
    line-height: 1.5;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
  }

  .config-form {
    max-width: 640px;
  }

  .form-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
  }

  .form-group {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .form-error {
    color: var(--error);
    font-size: 0.875rem;
    padding: 8px 12px;
    background: rgba(255, 69, 58, 0.1);
    border-radius: 6px;
    margin-top: 16px;
  }

  .form-success {
    color: #22c55e;
    font-size: 0.875rem;
    padding: 8px 12px;
    background: rgba(34, 197, 94, 0.1);
    border-radius: 6px;
  }

  .form-actions {
    margin-top: 24px;
    display: flex;
    gap: 12px;
  }

  .file-row {
    display: flex;
    gap: 8px;
    align-items: center;
  }

  .file-row input {
    flex: 1;
  }

  .restore-result {
    margin-top: 16px;
  }

  .section-heading {
    margin-top: 20px;
    margin-bottom: 12px;
    font-size: 0.9375rem;
    color: var(--text-secondary);
    font-weight: 600;
  }

  .btn-sm {
    padding: 4px 10px;
    font-size: 0.75rem;
  }

  .resign-section {
    margin-top: 16px;
    padding: 16px;
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    border-radius: 8px;
  }

  .resign-section .text-muted {
    margin: 0 0 12px;
  }

  .resign-form {
    max-width: 300px;
  }

  .resign-form .form-actions {
    margin-top: 12px;
  }

  .store-test-results {
    margin-top: 16px;
    display: grid;
    gap: 8px;
  }

  .store-test-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 12px;
    border-radius: 6px;
    font-size: 0.875rem;
  }

  .store-test-name {
    font-weight: 500;
    text-transform: capitalize;
  }

  .test-pass {
    background: rgba(34, 197, 94, 0.1);
  }

  .test-pass .store-test-status {
    color: #22c55e;
  }

  .test-fail {
    background: rgba(255, 69, 58, 0.1);
  }

  .test-fail .store-test-status {
    color: var(--error);
  }
`;
