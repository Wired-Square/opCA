import { tauriInvoke, withLock } from "./tauri";
import type { CrlInfo, InspectCrlResult } from "./types";

export async function getCrlInfo(): Promise<CrlInfo> {
  return tauriInvoke<CrlInfo>("get_crl_info");
}

export async function backfillCrl(): Promise<CrlInfo> {
  return tauriInvoke<CrlInfo>("backfill_crl");
}

export async function inspectCrl(crlPem: string): Promise<InspectCrlResult> {
  return tauriInvoke<InspectCrlResult>("inspect_crl", { crlPem });
}

export async function generateCrl(): Promise<CrlInfo> {
  return withLock("generate_crl", () =>
    tauriInvoke<CrlInfo>("generate_crl"),
  );
}

export async function uploadCrl(): Promise<void> {
  return tauriInvoke<void>("upload_crl");
}

/** Audit-log a clipboard copy of the CRL document. The PEM doesn't travel
 * through this call — the frontend already has it. */
export async function recordCrlCopy(): Promise<void> {
  return tauriInvoke<void>("record_crl_copy");
}
