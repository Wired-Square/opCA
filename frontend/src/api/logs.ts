import { tauriInvoke } from "./tauri";

export async function getLogContents(): Promise<string> {
  return tauriInvoke<string>("get_log_contents");
}

export async function getLogPath(): Promise<string> {
  return tauriInvoke<string>("get_log_path");
}
