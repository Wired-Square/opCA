import { tauriInvoke } from "./tauri";
import type { DashboardData } from "./types";

export async function getDashboard(): Promise<DashboardData> {
  return tauriInvoke<DashboardData>("get_dashboard");
}
