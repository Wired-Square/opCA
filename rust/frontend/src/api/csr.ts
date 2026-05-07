import { tauriInvoke, withLock } from "./tauri";
import type {
  CsrListItem,
  DecodeCsrResult,
  CreateCsrRequest,
  CreateCsrResult,
  SignCsrRequest,
  SignCsrResult,
  ImportCsrCertRequest,
  GenerateCsrFromCertRequest,
  InspectCsrResult,
  CertListItem,
} from "./types";

export async function decodeCsr(csrPem: string): Promise<DecodeCsrResult> {
  return tauriInvoke<DecodeCsrResult>("decode_csr", { csrPem });
}

export async function listCsrs(
  status?: string,
): Promise<CsrListItem[]> {
  return tauriInvoke<CsrListItem[]>("list_csrs", { status: status ?? null });
}

export async function getCsrInfo(cn: string): Promise<CreateCsrResult> {
  return tauriInvoke<CreateCsrResult>("get_csr_info", { cn });
}

export async function createCsr(
  request: CreateCsrRequest,
): Promise<CreateCsrResult> {
  return withLock("create_csr", () =>
    tauriInvoke<CreateCsrResult>("create_csr", { request }),
  );
}

export async function signCsr(
  request: SignCsrRequest,
): Promise<SignCsrResult> {
  return withLock("sign_csr", () =>
    tauriInvoke<SignCsrResult>("sign_csr", { request }),
  );
}

export async function importCsrCert(
  request: ImportCsrCertRequest,
): Promise<CertListItem> {
  return withLock("import_csr_cert", () =>
    tauriInvoke<CertListItem>("import_csr_cert", { request }),
  );
}

export async function generateCsrFromCert(
  request: GenerateCsrFromCertRequest,
): Promise<CreateCsrResult> {
  return withLock("generate_csr_from_cert", () =>
    tauriInvoke<CreateCsrResult>("generate_csr_from_cert", { request }),
  );
}

export async function inspectCsr(csrPem: string): Promise<InspectCsrResult> {
  return tauriInvoke<InspectCsrResult>("inspect_csr", { csrPem });
}
