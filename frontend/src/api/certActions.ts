import type { useNavigate } from "@solidjs/router";
import { rekeyCert, renewCert } from "./certs";
import type { CertListItem, KeyAlgorithm } from "./types";
import type { KebabItem } from "../components/KebabMenu";

/** How a certificate is named in confirmations and result messages. Shared so
 * the list, the detail page and the confirm dialogs cannot drift apart. */
export function certLabel(cert: { cn?: string | null; serial?: string | null }): string {
  return cert.cn ?? cert.serial ?? "this certificate";
}


/** Only a revoked or expired certificate can be deleted, and never the CA. */
export function canDeleteCert(cert: CertListItem): boolean {
  const status = cert.status?.toLowerCase();
  return (status === "revoked" || status === "expired") && cert.cert_type !== "ca";
}

type Navigate = ReturnType<typeof useNavigate>;

export interface CertActionHandlers {
  onRekey: () => void;
  onRenew: () => void;
  onRevoke: () => void;
  onDelete: () => void;
  onIgnore: () => void;
  onUnignore: () => void;
}

/** Build a certificate's kebab menu items, gated on its state. Shared by the
 * certificates list and the detail page so the two can't drift apart; each
 * caller supplies its own action handlers. */
export function certKebabItems(
  cert: CertListItem,
  h: CertActionHandlers,
  disabled?: boolean,
): KebabItem[] {
  const status = cert.status?.toLowerCase();
  const items: KebabItem[] = [{ label: "Rekey", disabled, onSelect: h.onRekey }];
  if (status === "valid") {
    items.push({ label: "Renew", disabled, onSelect: h.onRenew });
    items.push({ label: "Revoke", danger: true, disabled, onSelect: h.onRevoke });
  }
  if ((status === "expired" || cert.expiring_soon) && !cert.ignored_at && !cert.superseded_by) {
    items.push({ label: "Ignore", disabled, onSelect: h.onIgnore });
  }
  if (cert.ignored_at) {
    items.push({ label: "Unignore", disabled, onSelect: h.onUnignore });
  }
  if (canDeleteCert(cert)) {
    items.push({ label: "Delete", danger: true, disabled, onSelect: h.onDelete });
  }
  return items;
}

/** Rekey `serial` and navigate to the new cert, surfacing its new key + cert.
 * The backend persist (1Password + private store) already happened in
 * `rekey_cert`, so there's nothing more to sync here. */
export async function rekeyAndGo(
  navigate: Navigate,
  serial: string,
  keyAlgorithm: KeyAlgorithm | null,
): Promise<void> {
  const result = await rekeyCert(serial, keyAlgorithm);
  navigate(`/certs/${result.serial}?freshFrom=${serial}&op=rekey`);
}

/** Renew `serial` and navigate to the new cert. */
export async function renewAndGo(navigate: Navigate, serial: string): Promise<void> {
  const result = await renewCert(serial);
  navigate(`/certs/${result.serial}?freshFrom=${serial}&op=renew`);
}
