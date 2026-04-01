import { Show, For, createSignal, onMount, onCleanup } from "solid-js";
import {
  vaultBackup,
  vaultRestore,
  vaultInfo,
  vaultDefaultFilename,
  generatePassword,
  storePasswordInOp,
  fileMd5,
} from "../api/vault-backup";
import { getCaConfig } from "../api/ca";
import Spinner from "../components/Spinner";
import VaultPicker from "../components/VaultPicker";
import { invoke } from "@tauri-apps/api/core";
import { useNavigate, useSearchParams } from "@solidjs/router";
import { appState, setAppState, hasCA, type VaultState } from "../stores/app";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { BackupInfoResult, RestoreResult } from "../api/types";
import "../styles/pages/vault.css";

type Tab = "backup" | "restore" | "info";

export default function Vault() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const defaultTab = hasCA() ? "backup" : "restore";
  const initialTab = (["backup", "restore", "info"] as Tab[]).includes(searchParams.tab as Tab)
    ? (searchParams.tab as Tab)
    : defaultTab;
  const [tab, setTab] = createSignal<Tab>(
    !hasCA() && initialTab === "backup" ? "restore" : initialTab,
  );

  // Backup state
  const [backupPath, setBackupPath] = createSignal("");
  const [backupPassword, setBackupPassword] = createSignal("");
  const [backupConfirm, setBackupConfirm] = createSignal("");
  const [backingUp, setBackingUp] = createSignal(false);
  const [backupSuccess, setBackupSuccess] = createSignal<string | null>(null);
  const [backupError, setBackupError] = createSignal<string | null>(null);

  // Store transfer state
  const [hasBackupStore, setHasBackupStore] = createSignal(false);
  const [transferToStore, setTransferToStore] = createSignal(false);

  // Password generation / 1Password storage state
  const [storeInOp, setStoreInOp] = createSignal(false);
  const [storeTitle, setStoreTitle] = createSignal("");
  const [storeVault, setStoreVault] = createSignal("");
  const [storeWarning, setStoreWarning] = createSignal<string | null>(null);
  const [backupMd5, setBackupMd5] = createSignal<string | null>(null);

  // Restore state
  const [restorePath, setRestorePath] = createSignal("");
  const [restoreMd5, setRestoreMd5] = createSignal<string | null>(null);
  const [restorePassword, setRestorePassword] = createSignal("");
  const [restoring, setRestoring] = createSignal(false);
  const [restoreResult, setRestoreResult] = createSignal<RestoreResult | null>(null);
  const [restoreError, setRestoreError] = createSignal<string | null>(null);

  // Info state
  const [infoPath, setInfoPath] = createSignal("");
  const [infoPassword, setInfoPassword] = createSignal("");
  const [loadingInfo, setLoadingInfo] = createSignal(false);
  const [infoResult, setInfoResult] = createSignal<BackupInfoResult | null>(null);
  const [infoError, setInfoError] = createSignal<string | null>(null);

  // Progress events from backend
  const [progressMsg, setProgressMsg] = createSignal<string | null>(null);
  let unlistenProgress: UnlistenFn | undefined;

  onMount(async () => {
    unlistenProgress = await listen<string>("vault-progress", (event) => {
      setProgressMsg(event.payload);
    });
    try {
      const filename = await vaultDefaultFilename();
      setBackupPath(filename);
    } catch {
      // Ignore — user can type path manually
    }
    try {
      const config = await getCaConfig();
      setHasBackupStore(!!config.ca_backup_store);
    } catch {
      // Ignore — backup store checkbox simply stays hidden
    }
  });

  onCleanup(() => {
    unlistenProgress?.();
  });

  // --- File dialogs ---

  async function browseBackupSave() {
    const { save } = await import("@tauri-apps/plugin-dialog");
    const path = await save({
      defaultPath: backupPath() || undefined,
      filters: [{ name: "opCA Backup", extensions: ["opca"] }],
    });
    if (path) setBackupPath(path);
  }

  async function browseOpen(setter: (v: string) => void, current: string) {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const path = await open({
      defaultPath: current || undefined,
      multiple: false,
      filters: [{ name: "opCA Backup", extensions: ["opca"] }],
    });
    if (path) setter(path as string);
  }

  // --- File MD5 ---

  async function computeRestoreMd5(path: string) {
    if (!path.trim()) {
      setRestoreMd5(null);
      return;
    }
    try {
      const hash = await fileMd5(path.trim());
      setRestoreMd5(hash);
    } catch {
      setRestoreMd5(null);
    }
  }

  // --- Password generation ---

  async function handleGenerate() {
    try {
      const pw = await generatePassword();
      setBackupPassword(pw);
      setBackupConfirm(pw);
      // Auto-enable 1Password storage — a generated password is unrecoverable otherwise
      setStoreInOp(true);
      if (!storeTitle()) {
        const date = new Date().toISOString().slice(0, 10);
        setStoreTitle(`Vault Backup: ${appState.vault} ${date}`);
      }
    } catch (e) {
      setBackupError(String(e));
    }
  }

  // --- Backup ---

  async function handleBackup() {
    setBackupError(null);
    setBackupSuccess(null);
    setStoreWarning(null);

    const path = backupPath().trim();
    if (!path) {
      setBackupError("Please specify an output file.");
      return;
    }
    const pw = backupPassword();
    if (!pw) {
      setBackupError("Please enter a password.");
      return;
    }
    if (pw !== backupConfirm()) {
      setBackupError("Passwords do not match.");
      return;
    }
    if (storeInOp() && !storeTitle().trim()) {
      setBackupError("Please enter a title for the password item.");
      return;
    }

    setBackingUp(true);
    setProgressMsg(null);
    setBackupMd5(null);
    try {
      const md5Hash = await vaultBackup(path, pw, transferToStore());
      setBackupMd5(md5Hash);

      // Store password in 1Password as a separate step — backup already succeeded
      if (storeInOp()) {
        setProgressMsg("Storing password in 1Password\u2026");
        try {
          const vault = storeVault().trim() || undefined;
          await storePasswordInOp(pw, storeTitle().trim(), vault, md5Hash);
        } catch (e) {
          setStoreWarning(`Backup saved but failed to store password: ${e}`);
        }
      }

      const parts = [`Backup saved to ${path}`];
      if (transferToStore()) parts.push("transferred to store");
      if (storeInOp() && !storeWarning()) parts.push("password stored in 1Password");
      setBackupSuccess(parts.join(", "));

      setBackupPassword("");
      setBackupConfirm("");
    } catch (e) {
      setBackupError(String(e));
    } finally {
      setBackingUp(false);
      setProgressMsg(null);
    }
  }

  // --- Restore ---

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
      // Navigate to dashboard after a short delay so the user sees the success message
      setTimeout(() => navigate("/dashboard"), 1500);
    } catch (e) {
      setRestoreError(String(e));
    } finally {
      setRestoring(false);
      setProgressMsg(null);
    }
  }

  // --- Info ---

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
    <div class="page-vault">
      <div class="page-header">
        <h2>Vault</h2>
      </div>

      <div class="tab-bar">
        <button
          class={`tab-btn ${tab() === "backup" ? "tab-active" : ""}`}
          onClick={() => setTab("backup")}
          disabled={!hasCA()}
          title={!hasCA() ? "Initialise or restore a CA first" : undefined}
        >Backup</button>
        <button
          class={`tab-btn ${tab() === "restore" ? "tab-active" : ""}`}
          onClick={() => setTab("restore")}
          disabled={hasCA()}
          title={hasCA() ? "Cannot restore over a valid CA" : undefined}
        >Restore</button>
        <button
          class={`tab-btn ${tab() === "info" ? "tab-active" : ""}`}
          onClick={() => setTab("info")}
        >Info</button>
      </div>

      <div class="tab-content">
        {/* ---- Backup tab ---- */}
        <Show when={tab() === "backup"}>
          <div class="vault-form">
            <label class="form-label">Output file</label>
            <div class="file-row">
              <input
                type="text"
                class="form-input"
                placeholder="e.g. /tmp/my-vault.opca"
                value={backupPath()}
                onInput={(e) => setBackupPath(e.currentTarget.value)}
                autocomplete="off"
                autocorrect="off"
                autocapitalize="off"
                spellcheck={false}
              />
              <button class="btn-ghost" onClick={browseBackupSave}>Browse</button>
            </div>

            <label class="form-label">Password</label>
            <div class="file-row">
              <input
                type="password"
                class="form-input"
                placeholder="Encryption password"
                value={backupPassword()}
                onInput={(e) => setBackupPassword(e.currentTarget.value)}
                autocomplete="off"
                autocorrect="off"
                autocapitalize="off"
                spellcheck={false}
              />
              <button class="btn-ghost" onClick={handleGenerate} disabled={backingUp()}>
                Generate
              </button>
            </div>

            <label class="form-label">Confirm password</label>
            <input
              type="password"
              class="form-input"
              placeholder="Re-enter password"
              value={backupConfirm()}
              onInput={(e) => setBackupConfirm(e.currentTarget.value)}
              autocomplete="off"
              autocorrect="off"
              autocapitalize="off"
              spellcheck={false}
            />

            <label class="checkbox-row">
              <input
                type="checkbox"
                checked={storeInOp()}
                onChange={(e) => setStoreInOp(e.currentTarget.checked)}
              />
              Store password in 1Password
            </label>

            <Show when={storeInOp()}>
              <label class="form-label">Item title</label>
              <input
                type="text"
                class="form-input"
                placeholder="e.g. Vault Backup Password"
                value={storeTitle()}
                onInput={(e) => setStoreTitle(e.currentTarget.value)}
                autocomplete="off"
                autocorrect="off"
                autocapitalize="off"
                spellcheck={false}
              />

              <label class="form-label">Destination vault (optional)</label>
              <VaultPicker
                value={storeVault()}
                onChange={setStoreVault}
                placeholder="Leave blank for current vault"
              />
            </Show>

            <Show when={hasBackupStore()}>
              <label class="checkbox-row">
                <input
                  type="checkbox"
                  checked={transferToStore()}
                  onChange={(e) => setTransferToStore(e.currentTarget.checked)}
                />
                Transfer backup to store
              </label>
            </Show>

            <div class="action-row">
              <button class="btn-primary" onClick={handleBackup} disabled={backingUp()}>
                {backingUp() ? "Backing up\u2026" : "Backup"}
              </button>
            </div>

            <Show when={backingUp() && progressMsg()}>
              <Spinner message={progressMsg()!} />
            </Show>
            <Show when={backupError()}>
              <p class="page-error" role="alert">{backupError()}</p>
            </Show>
            <Show when={storeWarning()}>
              <p class="page-warning">{storeWarning()}</p>
            </Show>
            <Show when={backupSuccess()}>
              <p class="page-success">{backupSuccess()}</p>
              <Show when={backupMd5()}>
                <div class="md5-hash">
                  <span class="md5-label">MD5:</span> <code>{backupMd5()}</code>
                </div>
              </Show>
            </Show>
          </div>
        </Show>

        {/* ---- Restore tab ---- */}
        <Show when={tab() === "restore"}>
          <div class="vault-form">
            <label class="form-label">Backup file</label>
            <div class="file-row">
              <input
                type="text"
                class="form-input"
                placeholder="e.g. /tmp/my-vault.opca"
                value={restorePath()}
                onInput={(e) => { setRestorePath(e.currentTarget.value); setRestoreMd5(null); }}
                onBlur={(e) => computeRestoreMd5(e.currentTarget.value)}
                autocomplete="off"
                autocorrect="off"
                autocapitalize="off"
                spellcheck={false}
              />
              <button class="btn-ghost" onClick={async () => {
                const prev = restorePath();
                await browseOpen((v) => { setRestorePath(v); computeRestoreMd5(v); }, prev);
              }}>
                Browse
              </button>
            </div>

            <Show when={restoreMd5()}>
              <div class="md5-hash">
                <span class="md5-label">MD5:</span> <code>{restoreMd5()}</code>
              </div>
            </Show>

            <label class="form-label">Password</label>
            <input
              type="password"
              class="form-input"
              placeholder="Decryption password"
              value={restorePassword()}
              onInput={(e) => setRestorePassword(e.currentTarget.value)}
              autocomplete="off"
              autocorrect="off"
              autocapitalize="off"
              spellcheck={false}
            />

            <div class="action-row">
              <button class="btn-warning" onClick={handleRestore} disabled={restoring()}>
                {restoring() ? "Restoring\u2026" : "Restore"}
              </button>
            </div>

            <Show when={restoring() && progressMsg()}>
              <Spinner message={progressMsg()!} />
            </Show>
            <Show when={restoreError()}>
              <p class="page-error" role="alert">{restoreError()}</p>
            </Show>
            <Show when={restoreResult()}>
              {(r) => (
                <div class="result-section">
                  <p class="page-success">
                    Restore complete — {r().items_restored} item{r().items_restored !== 1 ? "s" : ""} restored.
                  </p>
                  <Show when={r().item_breakdown.length > 0}>
                    <div class="detail-grid">
                      <For each={r().item_breakdown}>
                        {(entry) => (
                          <div class="detail-row">
                            <span class="detail-label">{entry.item_type}</span>
                            <span class="detail-value">{entry.count}</span>
                          </div>
                        )}
                      </For>
                    </div>
                  </Show>
                </div>
              )}
            </Show>
          </div>
        </Show>

        {/* ---- Info tab ---- */}
        <Show when={tab() === "info"}>
          <div class="vault-form">
            <label class="form-label">Backup file</label>
            <div class="file-row">
              <input
                type="text"
                class="form-input"
                placeholder="e.g. /tmp/my-vault.opca"
                value={infoPath()}
                onInput={(e) => setInfoPath(e.currentTarget.value)}
                autocomplete="off"
                autocorrect="off"
                autocapitalize="off"
                spellcheck={false}
              />
              <button class="btn-ghost" onClick={() => browseOpen(setInfoPath, infoPath())}>
                Browse
              </button>
            </div>

            <label class="form-label">Password</label>
            <input
              type="password"
              class="form-input"
              placeholder="Decryption password"
              value={infoPassword()}
              onInput={(e) => setInfoPassword(e.currentTarget.value)}
              autocomplete="off"
              autocorrect="off"
              autocapitalize="off"
              spellcheck={false}
            />

            <div class="action-row">
              <button class="btn-primary" onClick={handleInfo} disabled={loadingInfo()}>
                {loadingInfo() ? "Reading\u2026" : "Show Info"}
              </button>
            </div>

            <Show when={infoError()}>
              <p class="page-error" role="alert">{infoError()}</p>
            </Show>

            <Show when={loadingInfo()}>
              <Spinner message="Decrypting backup\u2026" />
            </Show>

            <Show when={infoResult()}>
              {(r) => (
                <div class="result-section">
                  <div class="detail-grid">
                    <Row label="opCA Version" value={r().opca_version} />
                    <Row label="Vault Name" value={r().vault_name} />
                    <Row label="Backup Date" value={r().backup_date} />
                    <Row label="Item Count" value={String(r().item_count)} />
                  </div>

                  <Show when={r().item_breakdown.length > 0}>
                    <h3 class="section-heading">Item Breakdown</h3>
                    <div class="detail-grid">
                      <For each={r().item_breakdown}>
                        {(entry) => (
                          <Row label={entry.item_type} value={String(entry.count)} />
                        )}
                      </For>
                    </div>
                  </Show>
                </div>
              )}
            </Show>
          </div>
        </Show>
      </div>

    </div>
  );
}

function Row(props: { label: string; value: string | null | undefined }) {
  return (
    <div class="detail-row">
      <span class="detail-label">{props.label}</span>
      <span class="detail-value">{props.value ?? "\u2014"}</span>
    </div>
  );
}

