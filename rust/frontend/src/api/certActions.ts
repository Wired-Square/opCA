import type { useNavigate } from "@solidjs/router";
import { rekeyCert, renewCert } from "./certs";
import type { CertListItem } from "./types";
import type { KebabItem } from "../components/KebabMenu";

type Navigate = ReturnType<typeof useNavigate>;

export interface CertActionHandlers {
  onRekey: () => void;
  onRenew: () => void;
  onRevoke: () => void;
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
  return items;
}

/** Rekey `serial` and navigate to the new cert, surfacing its new key + cert.
 * The backend persist (1Password + private store) already happened in
 * `rekey_cert`, so there's nothing more to sync here. */
export async function rekeyAndGo(navigate: Navigate, serial: string): Promise<void> {
  const result = await rekeyCert(serial);
  navigate(`/certs/${result.serial}?freshFrom=${serial}&op=rekey`);
}

/** Renew `serial` and navigate to the new cert. */
export async function renewAndGo(navigate: Navigate, serial: string): Promise<void> {
  const result = await renewCert(serial);
  navigate(`/certs/${result.serial}?freshFrom=${serial}&op=renew`);
}
