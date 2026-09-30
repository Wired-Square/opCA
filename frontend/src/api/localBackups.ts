import { tauriInvoke, withLock } from "./tauri";
import type { LocalBackupsInfo } from "./types";
import type { VaultState } from "../stores/app";

export async function getLocalBackups(): Promise<LocalBackupsInfo> {
  return tauriInvoke<LocalBackupsInfo>("get_local_backups");
}

export async function setLocalBackupEnabled(enabled: boolean): Promise<void> {
  return tauriInvoke<void>("set_local_backup_enabled", { enabled });
}

export async function openLocalBackupsFolder(): Promise<void> {
  return tauriInvoke<void>("open_local_backups_folder");
}

export async function restoreLocalBackup(path: string): Promise<VaultState> {
  return withLock("restore_local_backup", () =>
    tauriInvoke<VaultState>("restore_local_backup", { path }),
  );
}
