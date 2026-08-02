import { invoke } from "@tauri-apps/api/core";
import { beginOp, endOp, isVisibleOp } from "../stores/operation";

/**
 * Typed wrapper around Tauri's invoke.
 * Normalises the rejection to an `Error` with a clean message and tracks the
 * active operation in the sidebar status indicator. Callers surface the
 * failure themselves — through a result banner or a page-error line.
 */
export async function tauriInvoke<T>(
  cmd: string,
  args?: Record<string, unknown>,
): Promise<T> {
  const visible = isVisibleOp(cmd);
  try {
    if (visible) beginOp(cmd);
    return await invoke<T>(cmd, args);
  } catch (err) {
    throw new Error(typeof err === "string" ? err : String(err));
  } finally {
    if (visible) endOp(cmd);
  }
}

/**
 * Execute a mutation operation with vault lock acquisition.
 *
 * Acquires the lock before calling `fn`, releases it afterwards
 * (even on failure).
 */
export async function withLock<T>(
  operation: string,
  fn: () => Promise<T>,
): Promise<T> {
  await tauriInvoke("acquire_lock", { operation });
  try {
    return await fn();
  } finally {
    await tauriInvoke("release_lock");
    // Sync the database to the private store (if configured) without blocking:
    // the backend snapshots under a brief lock then uploads off the connection
    // lock, so this never delays the screen refresh. Skipped when unchanged.
    void invoke("sync_private_store").catch(() => {});
  }
}
