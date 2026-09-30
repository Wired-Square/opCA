import { For, Show, createEffect, createResource, createSignal } from "solid-js";
import { useNavigate } from "@solidjs/router";
import Modal from "./Modal";
import Spinner from "./Spinner";
import PageError from "./PageError";
import BackupAge, { backupAgePhrase } from "./BackupAge";
import { getLocalBackups, restoreLocalBackup } from "../api/localBackups";
import { errorMessage } from "../api/tauri";
import { appState, disconnect, setAppState } from "../stores/app";
import { formatLocalDateTime } from "../utils/dates";
import type { LocalBackupEntry } from "../api/types";

const [recoveryOpen, setRecoveryOpen] = createSignal(false);
export { recoveryOpen, setRecoveryOpen };

function formatSize(bytes: number): string {
  return `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

/**
 * Offered when the vault's CA_Database can't be loaded: pick a local backup,
 * confirm with its age spelt out, and restore it to 1Password.
 */
export default function DatabaseRecoveryDialog() {
  const navigate = useNavigate();
  const [info] = createResource(recoveryOpen, getLocalBackups);
  const [selected, setSelected] = createSignal<LocalBackupEntry | null>(null);
  const [confirming, setConfirming] = createSignal(false);
  const [restoring, setRestoring] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  createEffect(() => {
    const backups = info()?.backups ?? [];
    setSelected(backups.find((b) => b.cert_count !== null) ?? null);
    setConfirming(false);
    setError(null);
  });

  async function handleRestore() {
    const backup = selected();
    if (!backup) return;
    setRestoring(true);
    setError(null);
    try {
      const state = await restoreLocalBackup(backup.path);
      setAppState("vaultState", state);
      setRecoveryOpen(false);
      navigate("/dashboard", { replace: true });
    } catch (e) {
      setError(errorMessage(e));
      setConfirming(false);
    } finally {
      setRestoring(false);
    }
  }

  async function handleDisconnect() {
    setRecoveryOpen(false);
    await disconnect();
    navigate("/");
  }

  return (
    <Modal open={recoveryOpen()} onClose={() => !restoring() && setRecoveryOpen(false)} title="CA Database Unreadable">
      <p class="confirm-message">
        The CA database in <span class="mono">{appState.vault}</span> can't be read, so the CA can't be loaded.
      </p>
      <PageError message={info()?.database_error} placement="form" class="mono mb-3" />

      <Show when={!info.loading} fallback={<Spinner message="Looking for local backups…" />}>
        <PageError message={info.error} />

        <Show
          when={(info()?.backups.length ?? 0) > 0}
          fallback={
            <div>
              <p>No local backups of this vault's database were found on this computer.</p>
              <p class="text-muted text-sm">
                Other places a good copy may exist: the <strong>CA_Database</strong> item's history in the
                1Password app, or the private-store (S3) copy if one is configured.
              </p>
            </div>
          }
        >
          <Show
            when={confirming() && selected()}
            fallback={
              <>
                <h4 class="section-heading">Restore from a local backup</h4>
                <div class="data-table-wrap">
                  <table class="data-table">
                    <thead>
                      <tr>
                        <th class="checkbox-col" />
                        <th>Taken</th>
                        <th>Certificates</th>
                        <th>Size</th>
                        <th>Vault</th>
                      </tr>
                    </thead>
                    <tbody>
                      <For each={info()!.backups}>
                        {(backup) => {
                          const readable = backup.cert_count !== null;
                          return (
                            <tr
                              class="data-table-row"
                              classList={{
                                "data-table-row-selected": selected()?.path === backup.path,
                                "text-muted": !readable,
                              }}
                              onClick={() => readable && setSelected(backup)}
                            >
                              <td class="checkbox-col">
                                <input
                                  type="radio"
                                  class="table-checkbox"
                                  name="recovery-backup"
                                  checked={selected()?.path === backup.path}
                                  disabled={!readable}
                                  onChange={() => setSelected(backup)}
                                />
                              </td>
                              <td><BackupAge takenAt={backup.taken_at} /></td>
                              <td>{readable ? backup.cert_count : "unreadable"}</td>
                              <td>{formatSize(backup.size)}</td>
                              <td>{backup.source?.vault ?? "\u2014"}</td>
                            </tr>
                          );
                        }}
                      </For>
                    </tbody>
                  </table>
                </div>
                <p class="text-muted text-sm mt-3">
                  Backups folder: <span class="mono">{info()!.dir}</span>
                </p>
              </>
            }
          >
            {(backup) => (
              <p class="confirm-message">
                Restore the backup from <strong>{backupAgePhrase(backup().taken_at)}</strong>{" "}
                ({formatLocalDateTime(new Date(backup().taken_at))})? Anything changed in this CA since then, on
                any machine, will be lost. The unreadable copy from 1Password is kept in the backups folder.
              </p>
            )}
          </Show>
        </Show>
      </Show>

      <PageError message={error()} placement="form" />

      <div class="form-actions">
        <Show
          when={confirming()}
          fallback={
            <button class="btn-primary" onClick={() => setConfirming(true)} disabled={!selected()}>
              Restore selected backup
            </button>
          }
        >
          <button class="btn-primary" onClick={handleRestore} disabled={restoring()}>
            {restoring() ? "Restoring…" : "Restore"}
          </button>
          <button class="btn-ghost" onClick={() => setConfirming(false)} disabled={restoring()}>
            Back
          </button>
        </Show>
        <button class="btn-ghost" onClick={handleDisconnect} disabled={restoring()}>
          Disconnect
        </button>
      </div>
    </Modal>
  );
}
