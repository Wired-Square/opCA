import { tauriInvoke, withLock } from "./tauri";
import type { CertListItem, ExternalCertListItem, CertDetail, CreateCertRequest, ImportCertRequest, ImportCertResult } from "./types";

export async function listCerts(): Promise<CertListItem[]> {
  return tauriInvoke<CertListItem[]>("list_certs");
}

export async function listExternalCerts(): Promise<ExternalCertListItem[]> {
  return tauriInvoke<ExternalCertListItem[]>("list_external_certs");
}

export async function getCertInfo(serial: string): Promise<CertDetail> {
  return tauriInvoke<CertDetail>("get_cert_info", { serial });
}

export async function backfillCert(serial: string): Promise<CertDetail> {
  return tauriInvoke<CertDetail>("backfill_cert", { serial });
}

export async function createCert(request: CreateCertRequest): Promise<CertListItem> {
  return withLock("create_cert", () =>
    tauriInvoke<CertListItem>("create_cert", { request }),
  );
}

export async function revokeCert(serial: string): Promise<boolean> {
  return withLock("revoke_cert", () =>
    tauriInvoke<boolean>("revoke_cert", { serial }),
  );
}

export async function renewCert(serial: string): Promise<string> {
  return withLock("renew_cert", () =>
    tauriInvoke<string>("renew_cert", { serial }),
  );
}

export async function rekeyCert(serial: string): Promise<string> {
  return withLock("rekey_cert", () =>
    tauriInvoke<string>("rekey_cert", { serial }),
  );
}

export async function importCert(request: ImportCertRequest): Promise<ImportCertResult> {
  return withLock("import_cert", () =>
    tauriInvoke<ImportCertResult>("import_cert", { request }),
  );
}
