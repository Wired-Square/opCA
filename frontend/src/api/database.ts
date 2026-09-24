import { tauriInvoke } from "./tauri";
import type { DatabaseInfo, LogEntry } from "./types";

export async function getDatabaseInfo(): Promise<DatabaseInfo> {
  return tauriInvoke<DatabaseInfo>("get_database_info");
}

export async function getActionLog(): Promise<LogEntry[]> {
  return tauriInvoke<LogEntry[]>("get_action_log");
}
