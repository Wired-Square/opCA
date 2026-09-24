import { tauriInvoke } from "./tauri";
import type { VaultInfo } from "./types";

export async function listVaults(
  account?: string | null,
): Promise<VaultInfo[]> {
  return tauriInvoke<VaultInfo[]>("list_vaults", {
    account: account ?? null,
  });
}

export async function createVault(
  name: string,
  account: string | null,
): Promise<VaultInfo> {
  return tauriInvoke<VaultInfo>("create_vault", { name, account });
}
