import { tauriInvoke, withLock } from "./tauri";
import type {
  DkimKeyItem,
  DkimKeyDetail,
  CreateDkimRequest,
  CreateDkimResult,
  DkimVerifyResult,
  DkimRoute53Result,
  DkimCopyKind,
} from "./types";

export async function listDkimKeys(): Promise<DkimKeyItem[]> {
  return tauriInvoke<DkimKeyItem[]>("list_dkim_keys");
}

/** Pull the DKIM_<domain>_<selector> items out of 1Password and refresh the
 * local SQLite mirror. Used after the v10 migration and on Refresh. */
export async function syncDkimKeys(): Promise<number> {
  return withLock("sync_dkim_keys", () =>
    tauriInvoke<number>("sync_dkim_keys"),
  );
}

export async function getDkimInfo(
  domain: string,
  selector: string,
): Promise<DkimKeyDetail> {
  return tauriInvoke<DkimKeyDetail>("get_dkim_info", { domain, selector });
}

export async function backfillDkim(
  domain: string,
  selector: string,
): Promise<DkimKeyDetail> {
  return tauriInvoke<DkimKeyDetail>("backfill_dkim", { domain, selector });
}

export async function getDkimPrivateKey(
  domain: string,
  selector: string,
): Promise<string> {
  return tauriInvoke<string>("get_dkim_private_key", { domain, selector });
}

/** Audit-log a clipboard copy of a non-secret DKIM artefact. */
export async function recordDkimCopy(
  domain: string,
  selector: string,
  kind: DkimCopyKind,
): Promise<void> {
  return tauriInvoke<void>("record_dkim_copy", { domain, selector, kind });
}

export async function createDkimKey(
  request: CreateDkimRequest,
): Promise<CreateDkimResult> {
  return withLock("create_dkim", () =>
    tauriInvoke<CreateDkimResult>("create_dkim_key", { request }),
  );
}

export async function deleteDkimKey(
  domain: string,
  selector: string,
): Promise<boolean> {
  return withLock("delete_dkim", () =>
    tauriInvoke<boolean>("delete_dkim_key", { domain, selector }),
  );
}

export async function verifyDkimDns(
  domain: string,
  selector: string,
): Promise<DkimVerifyResult> {
  return tauriInvoke<DkimVerifyResult>("verify_dkim_dns", { domain, selector });
}

export async function deployDkimRoute53(
  domain: string,
  selector: string,
): Promise<DkimRoute53Result> {
  return tauriInvoke<DkimRoute53Result>("deploy_dkim_route53", { domain, selector });
}
