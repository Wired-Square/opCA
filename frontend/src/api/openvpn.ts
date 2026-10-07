import { tauriInvoke, withLock } from "./tauri";
import type {
  BulkGenerateProfileItem,
  BulkProfileResult,
  CertListItem,
  OpenVpnServerParams,
  OpenVpnTemplateItem,
  OpenVpnTemplateDetail,
  OpenVpnProfileItem,
  GenerateProfileRequest,
  ServerSetupRequest,
} from "./types";

export async function getOpenVpnParams(): Promise<OpenVpnServerParams> {
  return tauriInvoke<OpenVpnServerParams>("get_openvpn_params");
}

export async function generateOpenVpnDh(): Promise<OpenVpnServerParams> {
  return withLock("generate_dh", () =>
    tauriInvoke<OpenVpnServerParams>("generate_openvpn_dh"),
  );
}

export async function generateOpenVpnTa(): Promise<OpenVpnServerParams> {
  return withLock("generate_ta", () =>
    tauriInvoke<OpenVpnServerParams>("generate_openvpn_ta"),
  );
}

export async function setupOpenVpnServer(
  request: ServerSetupRequest,
): Promise<OpenVpnServerParams> {
  return withLock("setup_openvpn", () =>
    tauriInvoke<OpenVpnServerParams>("setup_openvpn_server", { request }),
  );
}

export async function listOpenVpnTemplates(): Promise<OpenVpnTemplateItem[]> {
  return tauriInvoke<OpenVpnTemplateItem[]>("list_openvpn_templates");
}

export async function getOpenVpnTemplate(
  name: string,
): Promise<OpenVpnTemplateDetail> {
  return tauriInvoke<OpenVpnTemplateDetail>("get_openvpn_template", { name });
}

export async function saveOpenVpnTemplate(
  name: string,
  content: string,
): Promise<boolean> {
  return withLock("save_template", () =>
    tauriInvoke<boolean>("save_openvpn_template", { name, content }),
  );
}

export async function deleteOpenVpnTemplate(name: string): Promise<boolean> {
  return withLock("delete_template", () =>
    tauriInvoke<boolean>("delete_openvpn_template", { name }),
  );
}

/** Template fields still on the 1Password OpenVPN item after a successful
 * import into the CA database; empty once archived or kept. */
export async function listOpenVpnVaultTemplates(): Promise<string[]> {
  return tauriInvoke<string[]>("list_openvpn_vault_templates");
}

export async function archiveOpenVpnVaultTemplates(): Promise<number> {
  return withLock("archive_templates", () =>
    tauriInvoke<number>("archive_openvpn_vault_templates"),
  );
}

export async function keepOpenVpnVaultTemplates(): Promise<void> {
  return withLock("keep_templates", () =>
    tauriInvoke<void>("keep_openvpn_vault_templates"),
  );
}

/** Valid `vpnclient` and `vpnserver` certificates, enriched with serial /
 * status / expiry so the picker can render a coloured serial badge. Sorted by
 * CN, then serial desc (current cert first within a renewed CN). The Add-profile
 * flow infers Client/Server from the chosen cert's `cert_type`. */
export async function listVpnCerts(): Promise<CertListItem[]> {
  return tauriInvoke<CertListItem[]>("list_vpn_certs");
}

/** Look up the VPN profile previously generated for a CN (DB-backed, no `op`
 * call). Returns null if the CN has no recorded profile. */
export async function getVpnProfileForCn(
  cn: string,
): Promise<OpenVpnProfileItem | null> {
  return tauriInvoke<OpenVpnProfileItem | null>("get_vpn_profile_for_cn", { cn });
}

export async function generateOpenVpnProfile(
  request: GenerateProfileRequest,
): Promise<OpenVpnProfileItem> {
  return withLock("generate_profile", () =>
    tauriInvoke<OpenVpnProfileItem>("generate_openvpn_profile", { request }),
  );
}

export async function listOpenVpnProfiles(): Promise<OpenVpnProfileItem[]> {
  return tauriInvoke<OpenVpnProfileItem[]>("list_openvpn_profiles");
}

/** Regenerate many profiles in one vault-lock cycle (typically the needs-regen
 * rows, against their replacement serials). Returns a per-profile result. */
export async function bulkGenerateOpenVpnProfiles(
  items: BulkGenerateProfileItem[],
): Promise<BulkProfileResult[]> {
  return withLock("bulk_generate_profile", () =>
    tauriInvoke<BulkProfileResult[]>("bulk_generate_openvpn_profiles", { items }),
  );
}

/** Register profiles WITHOUT generating their `.ovpn` documents (Add with
 * "Generate Profile" unticked). The rows flag for later generation. */
export async function addOpenVpnProfileEntries(
  items: BulkGenerateProfileItem[],
): Promise<BulkProfileResult[]> {
  return withLock("add_profile_entry", () =>
    tauriInvoke<BulkProfileResult[]>("add_openvpn_profile_entries", { items }),
  );
}

/** Remove a profile from the registry (row only; the `.ovpn` document stays). */
export async function deleteOpenVpnProfile(title: string): Promise<boolean> {
  return withLock("delete_profile", () =>
    tauriInvoke<boolean>("delete_openvpn_profile", { title }),
  );
}

export async function bulkDeleteOpenVpnProfiles(
  titles: string[],
): Promise<BulkProfileResult[]> {
  return withLock("bulk_delete_profile", () =>
    tauriInvoke<BulkProfileResult[]>("bulk_delete_openvpn_profiles", { titles }),
  );
}

export async function sendProfileToVault(
  title: string,
  cn: string,
  destVault: string,
): Promise<boolean> {
  return withLock("send_profile", () =>
    tauriInvoke<boolean>("send_profile_to_vault", {
      title,
      cn,
      destVault,
    }),
  );
}
