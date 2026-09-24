import { Show, For, createSignal, createResource, onMount, onCleanup } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { appState, setAppState, hasCA, type VaultState } from "../stores/app";
import { getCaInfo, getCaConfig, updateCaConfig, initCa, testStores, uploadCaCert, recordCaCertCopy } from "../api/ca";
import { listAwsCredentials, getAwsCredential, setAwsCredential } from "../api/aws";
import { vaultRestore, vaultInfo } from "../api/vault-backup";
import { formatDate } from "../utils/dates";
import { createCopiedSignal, writeClipboard } from "../utils/clipboard";
import TzToggle from "../components/TzToggle";
import Spinner from "../components/Spinner";
import SearchInput from "../components/SearchInput";
import Availability from "../components/Availability";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import { defaultKeyAlgorithm, type CaInfo, type CaConfig, type RestoreResult, type BackupInfoResult, type StoreTestResults, type AwsItemRef } from "../api/types";
import KeyAlgorithmSelect from "../components/KeyAlgorithmSelect";
import { ActionResultBanner, ActionResultLine } from "../components/ResultBanner";
import ResignCaDialog from "../components/ResignCaDialog";
import UploadPrompt from "../components/UploadPrompt";
import { createActionResult } from "../utils/actionResult";
import { createAction } from "../utils/action";
import { createPublishFlow } from "../utils/publishFlow";
import "../styles/pages/ca.css";

type Tab = "certificate" | "config" | "stores" | "init" | "restore" | "info";

export default function CA() {
  const [tab, setTab] = createSignal<Tab>(hasCA() ? "certificate" : "init");
  const [caInfo, { refetch: refetchCaInfo }] = createResource<CaInfo>(getCaInfo);
  const [caConfig, { refetch: refetchConfig }] = createResource<CaConfig>(getCaConfig);

  // Certificate-tab actions live up here so they can sit in the page header
  // beside the title, the way the CRL page does it.
  const [showResignDialog, setShowResignDialog] = createSignal(false);
  const outcome = createActionResult();
  const publish = createPublishFlow({
    upload: uploadCaCert,
    success: "Certificate uploaded to public store",
    outcome,
  });

  // Reading `.error` first: a resource getter rethrows, and the header reads
  // this before the tab body has gated on a loaded resource.
  const hasPublicStore = () => !caConfig.error && !!caConfig()?.ca_public_store;

  /** Certificate-tab feedback is owned by the shell now, so it would otherwise
   * outlive the tab it belongs to. */
  function selectTab(next: Tab) {
    setTab(next);
    publish.dismiss();
    outcome.clear();
  }

  function handleResigned(days: number) {
    refetchCaInfo();
    outcome.report(`CA certificate re-signed for ${days} days`);
    // Re-signing does not publish, so the store still holds the old
    // certificate — same gap the CRL page closes after Generate.
    if (hasPublicStore()) publish.offer();
  }

  return (
    <div class="page-ca">
      <div class="page-header">
        <h2>Certificate Authority</h2>
        <Show when={tab() === "certificate"}>
          <div class="header-actions">
            <button class="btn-ghost" onClick={() => setShowResignDialog(true)}>
              Re-sign Certificate
            </button>
            <Show when={hasPublicStore()}>
              <button class="btn-ghost" onClick={publish.handleUpload} disabled={publish.uploading()}>
                {publish.uploading() ? "Uploading…" : "Upload Certificate"}
              </button>
            </Show>
          </div>
        </Show>
      </div>

      <div class="tab-bar">
        <Show when={hasCA()}>
          <button
            class={`tab-btn ${tab() === "certificate" ? "tab-active" : ""}`}
            onClick={() => selectTab("certificate")}
          >Certificate</button>
          <button
            class={`tab-btn ${tab() === "config" ? "tab-active" : ""}`}
            onClick={() => selectTab("config")}
          >Configuration</button>
          <button
            class={`tab-btn ${tab() === "stores" ? "tab-active" : ""}`}
            onClick={() => selectTab("stores")}
          >Stores</button>
        </Show>
        <Show when={!hasCA()}>
          <button
            class={`tab-btn ${tab() === "init" ? "tab-active" : ""}`}
            onClick={() => selectTab("init")}
          >Initialise CA</button>
          <button
            class={`tab-btn ${tab() === "restore" ? "tab-active" : ""}`}
            onClick={() => selectTab("restore")}
          >Restore</button>
          <button
            class={`tab-btn ${tab() === "info" ? "tab-active" : ""}`}
            onClick={() => selectTab("info")}
          >Info</button>
        </Show>
      </div>

      <Show when={tab() === "certificate"}>
        <UploadPrompt
          flow={publish}
          message="Upload the re-signed certificate to the public store?"
        />

        <ActionResultBanner outcome={outcome} />

        <CertificateTab info={caInfo} />
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

      <ResignCaDialog
        open={showResignDialog()}
        onClose={() => setShowResignDialog(false)}
        onDone={handleResigned}
      />
    </div>
  );
}

function CertificateTab(props: { info: () => CaInfo | undefined }) {
  const [copied, markCopied] = createCopiedSignal();

  function copyPem() {
    const pem = props.info()?.cert_pem;
    if (pem) {
      void writeClipboard(pem);
      markCopied();
      void recordCaCertCopy();
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
              <div class="detail-row">
                <span class="detail-label">Stored Items</span>
                <div class="stored-items">
                  <Availability
                    label="Certificate"
                    available={info().cert_pem ? true : null}
                    onCopy={copyPem}
                    copied={copied()}
                  />
                  <Availability
                    label="Private Key"
                    available={info().has_private_key}
                    blocked="CA private keys cannot be copied from opCA. Retrieve from 1Password directly if absolutely necessary."
                  />
                </div>
              </div>
            </div>

            <Show when={info().cert_pem}>
              <div class="pem-section">
                <div class="pem-header">
                  <span class="pem-label">Certificate PEM</span>
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
  const outcome = createActionResult();
  const save = createAction(outcome);
  const [form, setForm] = createSignal<Partial<CaConfig>>({});

  const merged = () => ({ ...props.config(), ...form() } as CaConfig);
  const set = (key: keyof CaConfig, value: string | number | null) =>
    setForm((f) => ({ ...f, [key]: value || null }));

  const handleSave = () =>
    save.run({ success: "Configuration saved.", failure: "Save failed" }, async () => {
      await updateCaConfig(merged());
      setForm({});
      props.onSave();
    });

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

            <ActionResultLine outcome={outcome} />

            <div class="form-actions">
              <button class="btn-primary" onClick={handleSave} disabled={save.busy()}>
                {save.busy() ? "Saving…" : "Save Configuration"}
              </button>
            </div>
          </div>
        )}
      </Show>
    </div>
  );
}

function StoresTab(props: { config: () => CaConfig | undefined; onSave: () => void }) {
  const [testing, setTesting] = createSignal(false);
  const outcome = createActionResult();
  const save = createAction(outcome);
  const [testResults, setTestResults] = createSignal<StoreTestResults | null>(null);
  const [testError, setTestError] = createSignal<string | null>(null);
  const [form, setForm] = createSignal<Partial<CaConfig>>({});

  const merged = () => ({ ...props.config(), ...form() } as CaConfig);
  const set = (key: keyof CaConfig, value: string | null) =>
    setForm((f) => ({ ...f, [key]: value || null }));
  const usesS3 = () =>
    [merged().ca_public_store, merged().ca_private_store, merged().ca_backup_store].some(
      (uri) => uri?.startsWith("s3://"),
    );

  const handleSave = () =>
    save.run({ success: "Store settings saved.", failure: "Save failed" }, async () => {
      await updateCaConfig(merged());
      setForm({});
      props.onSave();
    });

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
              <FormField label="AWS Region" value={merged().ca_aws_region}
                onChange={(v) => set("ca_aws_region", v)} />
            </div>

            <ActionResultLine outcome={outcome} />

            <div class="form-actions">
              <button class="btn-primary" onClick={handleSave} disabled={save.busy()}>
                {save.busy() ? "Saving…" : "Save Stores"}
              </button>
              <button class="btn-ghost" onClick={handleTest} disabled={testing()}>
                {testing() ? "Testing…" : "Test Stores"}
              </button>
            </div>

            {/* Only S3 stores need AWS credentials — don't make an rsync/sftp
                CA pay for listing 1Password items. */}
            <Show when={usesS3()}>
              <AwsCredentialSection />
            </Show>

            <Show when={testing()}>
              <Spinner message="Testing store connections…" />
            </Show>

            <Show when={testError()}>
              <p class="form-error" role="alert">{testError()}</p>
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

/** Cached across mounts: the Stores tab is inside a `Show`, so Solid disposes
 * this section on every tab switch and would otherwise repeat the
 * multi-second `op item list` each time. Refresh clears it. */
let awsItemCache: AwsItemRef[] | undefined;

async function loadAwsItems(): Promise<AwsItemRef[]> {
  awsItemCache ??= await listAwsCredentials();
  return awsItemCache;
}

/** Picker for this user's AWS credential.
 *
 * Deliberately separate from the store URIs above: those are shared CA config,
 * but the AWS access key is personal — several operators share one CA and each
 * has their own. The selection is stored locally by the backend, keyed by
 * 1Password account. */
function AwsCredentialSection() {
  const [items, { refetch: refetchItems }] = createResource(loadAwsItems);
  const [selection, { refetch: refetchSelection }] = createResource(getAwsCredential);
  const [saving, setSaving] = createSignal(false);
  const [result, setResult] = createSignal<string | null>(null);
  // An account can hold hundreds of logins; default to the ones that look
  // like AWS keys, but let the filter be cleared to reach anything.
  const [filter, setFilter] = createSignal("aws");

  // Keeps the current selection visible even when the filter excludes it.
  const filtered = () => {
    const needle = filter().toLowerCase();
    const selected = selection()?.item_id;
    return (items() ?? []).filter(
      (i) => i.id === selected || i.title.toLowerCase().includes(needle),
    );
  };

  async function handleSelect(itemId: string) {
    setSaving(true);
    setResult(null);
    try {
      await setAwsCredential(itemId || null);
      await refetchSelection();
      setResult("ok");
    } catch (e) {
      setResult(String(e));
    } finally {
      setSaving(false);
    }
  }

  function handleRefresh() {
    awsItemCache = undefined;
    refetchItems();
  }

  return (
    <div class="aws-credential-section">
      <div class="form-label-row">
        <h3>Your AWS Credential</h3>
        <button class="btn-ghost" onClick={handleRefresh} disabled={items.loading}>
          Refresh
        </button>
      </div>
      <p class="aws-credential-hint">
        Stored on this machine only, for{" "}
        <strong>{selection()?.account ?? "the connected account"}</strong>. Other
        operators of this CA choose their own.
      </p>

      <Show when={!items.loading} fallback={<Spinner message="Loading 1Password items…" />}>
        <div class="form-grid">
          <div class="form-group">
            <label class="form-label">Filter</label>
            <SearchInput value={filter()} onInput={setFilter} placeholder="Filter items…" />
          </div>
          <div class="form-group">
            <label class="form-label">
              1Password Item ({filtered().length} of {items()?.length ?? 0})
            </label>
            <select
              class="form-select"
              disabled={saving()}
              value={selection()?.item_id ?? ""}
              onChange={(e) => handleSelect(e.currentTarget.value)}
            >
              <option value="">— none selected —</option>
              <For each={filtered()}>
                {(item) => (
                  <option value={item.id}>
                    {item.title} ({item.vault})
                  </option>
                )}
              </For>
            </select>
          </div>
        </div>
      </Show>

      <Show when={items.error}>
        <p class="form-error" role="alert">{String(items.error)}</p>
      </Show>
      <Show when={result() && result() !== "ok"}>
        <p class="form-error" role="alert">{result()}</p>
      </Show>
      <Show when={result() === "ok"}>
        <p class="form-success">AWS credential saved.</p>
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
    key_algorithm: defaultKeyAlgorithm("ca"),
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
          <KeyAlgorithmSelect
            value={form().key_algorithm ?? defaultKeyAlgorithm("ca")}
            onChange={(v) => setForm((f) => ({ ...f, key_algorithm: v }))}
          />
        </div>

        <Show when={error()}>
          <p class="form-error" role="alert">{error()}</p>
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
  let navTimer: number | undefined;

  onMount(async () => {
    unlistenProgress = await listen<string>("vault-progress", (event) => {
      setProgressMsg(event.payload);
    });
  });

  onCleanup(() => {
    unlistenProgress?.();
    clearTimeout(navTimer);
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

      navTimer = window.setTimeout(() => navigate("/dashboard"), 1500);
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
          <p class="form-error" role="alert">{restoreError()}</p>
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
          <p class="form-error" role="alert">{infoError()}</p>
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

