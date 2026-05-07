import { tauriInvoke, withLock } from "./tauri";
import type { CaInfo, CaConfig, StoreTestResults } from "./types";

export async function getCaInfo(): Promise<CaInfo> {
  return tauriInvoke<CaInfo>("get_ca_info");
}

export async function getCaConfig(): Promise<CaConfig> {
  return tauriInvoke<CaConfig>("get_ca_config");
}

export async function updateCaConfig(config: CaConfig): Promise<void> {
  return withLock("update_ca_config", () =>
    tauriInvoke("update_ca_config", { config }),
  );
}

export async function initCa(config: CaConfig): Promise<void> {
  return withLock("init_ca", () =>
    tauriInvoke("init_ca", { config }),
  );
}

export async function testStores(): Promise<StoreTestResults> {
  return tauriInvoke<StoreTestResults>("test_stores");
}

export async function uploadCaCert(): Promise<void> {
  return tauriInvoke<void>("upload_ca_cert");
}

export async function uploadCaDatabase(): Promise<void> {
  return tauriInvoke<void>("upload_ca_database");
}

export async function resignCa(caDays: number): Promise<CaInfo> {
  return withLock("resign_ca", () =>
    tauriInvoke<CaInfo>("resign_ca", { caDays }),
  );
}

/** Audit-log a clipboard copy of the CA certificate. Mirrors `recordCertCopy`
 * — the PEM doesn't travel through this call, the frontend already has it. */
export async function recordCaCertCopy(): Promise<void> {
  return tauriInvoke<void>("record_ca_cert_copy");
}
