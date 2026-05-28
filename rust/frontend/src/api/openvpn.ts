import { tauriInvoke, withLock } from "./tauri";
import type {
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

export async function listVpnClients(): Promise<string[]> {
  return tauriInvoke<string[]>("list_vpn_clients");
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

export async function sendProfileToVault(
  cn: string,
  destVault: string,
): Promise<boolean> {
  return withLock("send_profile", () =>
    tauriInvoke<boolean>("send_profile_to_vault", {
      cn,
      destVault,
    }),
  );
}
