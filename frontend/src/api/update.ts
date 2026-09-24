import { invoke } from "@tauri-apps/api/core";
import type { UpdateInfo } from "./types";

/**
 * Check for available updates from GitHub releases.
 *
 * Uses a raw invoke (not tauriInvoke) so that failures do not set the
 * global app error state — update checking is best-effort.
 */
export async function checkForUpdates(): Promise<UpdateInfo | null> {
  return invoke<UpdateInfo | null>("check_for_updates");
}
