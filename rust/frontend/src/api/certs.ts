import { tauriInvoke, withLock } from "./tauri";
import type {
  CertListItem,
  ExternalCertListItem,
  CertDetail,
  ExternalCertDetail,
  CreateCertRequest,
  ImportCertRequest,
  ImportCertResult,
  InspectCertificateResult,
} from "./types";

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

export async function getExternalCertInfo(serial: string): Promise<ExternalCertDetail> {
  return tauriInvoke<ExternalCertDetail>("get_external_cert_info", { serial });
}

export async function backfillExternalCert(serial: string): Promise<ExternalCertDetail> {
  return tauriInvoke<ExternalCertDetail>("backfill_external_cert", { serial });
}

export async function getCertPrivateKey(serial: string): Promise<string> {
  return tauriInvoke<string>("get_cert_private_key", { serial });
}

export async function getExternalCertPrivateKey(serial: string): Promise<string> {
  return tauriInvoke<string>("get_external_cert_private_key", { serial });
}

export async function inspectCertificate(certPem: string): Promise<InspectCertificateResult> {
  return tauriInvoke<InspectCertificateResult>("inspect_certificate", { certPem });
}

/** Audit-log a clipboard copy of a non-secret cert artefact. The PEM bytes
 * don't travel through this call — the frontend already has them. */
export async function recordCertCopy(
  scope: "local" | "external",
  serial: string,
  kind: "certificate" | "chain",
): Promise<void> {
  return tauriInvoke<void>("record_cert_copy", { scope, serial, kind });
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

export async function ignoreCert(serial: string, note?: string): Promise<void> {
  return withLock("ignore_cert", () =>
    tauriInvoke<void>("ignore_cert", { serial, note: note ?? null }),
  );
}

export async function unignoreCert(serial: string): Promise<void> {
  return withLock("unignore_cert", () =>
    tauriInvoke<void>("unignore_cert", { serial }),
  );
}

export async function importCert(request: ImportCertRequest): Promise<ImportCertResult> {
  return withLock("import_cert", () =>
    tauriInvoke<ImportCertResult>("import_cert", { request }),
  );
}
