import { tauriInvoke, withLock } from "./tauri";
import type {
  BulkCertResult,
  KeyAlgorithm,
  CertListItem,
  ExternalCertListItem,
  CertDetail,
  ExternalCertDetail,
  CreateCertRequest,
  ImportCertRequest,
  ImportCertResult,
  InspectCertificateResult,
  RenewRekeyResult,
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

/** `passphrase` returns the key as encrypted PKCS#8. */
export async function getCertPrivateKey(serial: string, passphrase?: string): Promise<string> {
  return tauriInvoke<string>("get_cert_private_key", { serial, passphrase: passphrase ?? null });
}

export async function getExternalCertPrivateKey(serial: string, passphrase?: string): Promise<string> {
  return tauriInvoke<string>("get_external_cert_private_key", { serial, passphrase: passphrase ?? null });
}

/** Drop the key the backend kept from the last cert detail backfill. */
export async function forgetPreloadedKey(): Promise<void> {
  return tauriInvoke<void>("forget_preloaded_key");
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

export async function deleteCert(serial: string): Promise<void> {
  return withLock("delete_cert", () =>
    tauriInvoke<void>("delete_cert", { serial }),
  );
}

export async function renewCert(serial: string): Promise<RenewRekeyResult> {
  return withLock("renew_cert", () =>
    tauriInvoke<RenewRekeyResult>("renew_cert", { serial }),
  );
}

export async function rekeyCert(
  serial: string,
  keyAlgorithm: KeyAlgorithm | null,
): Promise<RenewRekeyResult> {
  return withLock("rekey_cert", () =>
    tauriInvoke<RenewRekeyResult>("rekey_cert", { serial, keyAlgorithm }),
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

// --- Bulk operations ---------------------------------------------------------
// One Tauri command per action, wrapped in a single `withLock` so a batch of N
// certs costs one vault-lock cycle. Each returns a per-serial result vector.

export async function bulkRekeyCerts(
  serials: string[],
  keyAlgorithm: KeyAlgorithm | null,
): Promise<BulkCertResult[]> {
  return withLock("bulk_rekey", () =>
    tauriInvoke<BulkCertResult[]>("bulk_rekey_certs", { serials, keyAlgorithm }),
  );
}

export async function bulkRenewCerts(serials: string[]): Promise<BulkCertResult[]> {
  return withLock("bulk_renew", () =>
    tauriInvoke<BulkCertResult[]>("bulk_renew_certs", { serials }),
  );
}

export async function bulkRevokeCerts(serials: string[]): Promise<BulkCertResult[]> {
  return withLock("bulk_revoke", () =>
    tauriInvoke<BulkCertResult[]>("bulk_revoke_certs", { serials }),
  );
}

export async function bulkDeleteCerts(serials: string[]): Promise<BulkCertResult[]> {
  return withLock("bulk_delete", () =>
    tauriInvoke<BulkCertResult[]>("bulk_delete_certs", { serials }),
  );
}

export async function bulkIgnoreCerts(serials: string[], note?: string): Promise<BulkCertResult[]> {
  return withLock("bulk_ignore", () =>
    tauriInvoke<BulkCertResult[]>("bulk_ignore_certs", { serials, note: note ?? null }),
  );
}

export async function bulkUnignoreCerts(serials: string[]): Promise<BulkCertResult[]> {
  return withLock("bulk_unignore", () =>
    tauriInvoke<BulkCertResult[]>("bulk_unignore_certs", { serials }),
  );
}
