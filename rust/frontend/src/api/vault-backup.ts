import { tauriInvoke, withLock } from "./tauri";
import type { BackupInfoResult, RestoreResult } from "./types";

export async function vaultBackup(
  path: string,
  password: string,
  transferToStore: boolean,
): Promise<void> {
  return withLock("vault_backup", () =>
    tauriInvoke<void>("vault_backup", { path, password, transferToStore }),
  );
}

export async function vaultRestore(
  path: string,
  password: string,
  vault: string,
  account: string | null,
): Promise<RestoreResult> {
  // No withLock — vault_restore creates its own Op connection and handles
  // locking internally because the shared Op may have been lost after a
  // failed ensure_ca() on an empty vault.
  return tauriInvoke<RestoreResult>("vault_restore", {
    path,
    password,
    vault,
    account,
  });
}

export async function vaultInfo(
  path: string,
  password: string,
): Promise<BackupInfoResult> {
  return tauriInvoke<BackupInfoResult>("vault_info", { path, password });
}

export async function vaultDefaultFilename(): Promise<string> {
  return tauriInvoke<string>("vault_default_filename");
}

export async function generatePassword(): Promise<string> {
  return tauriInvoke<string>("generate_password");
}

export async function storePasswordInOp(
  password: string,
  itemTitle: string,
): Promise<void> {
  return tauriInvoke<void>("store_password_in_op", { password, itemTitle });
}
