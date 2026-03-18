import { createSignal } from "solid-js";
import { listen } from "@tauri-apps/api/event";

/** Human-readable labels for Tauri command names. */
const operationLabels: Record<string, string> = {
  // Connect
  connect: "Connecting to vault\u2026",
  disconnect: "Disconnecting\u2026",
  list_vaults: "Listing vaults\u2026",
  create_vault: "Creating vault\u2026",
  check_vault_state: "Checking vault\u2026",

  // Dashboard
  get_dashboard: "Loading dashboard\u2026",

  // CA
  get_ca_info: "Loading CA info\u2026",
  get_ca_config: "Loading CA config\u2026",
  update_ca_config: "Updating CA config\u2026",
  init_ca: "Initialising CA\u2026",
  test_stores: "Testing stores\u2026",
  upload_ca_cert: "Uploading CA certificate\u2026",
  upload_ca_database: "Uploading database\u2026",

  // Certificates
  list_certs: "Loading certificates\u2026",
  list_external_certs: "Loading external certs\u2026",
  get_cert_info: "Loading certificate\u2026",
  backfill_cert: "Retrieving certificate\u2026",
  create_cert: "Creating certificate\u2026",
  revoke_cert: "Revoking certificate\u2026",
  renew_cert: "Renewing certificate\u2026",
  import_cert: "Importing certificate\u2026",

  // CRL
  get_crl_info: "Loading CRL\u2026",
  generate_crl: "Generating CRL\u2026",
  upload_crl: "Uploading CRL\u2026",

  // CSR
  list_csrs: "Loading CSRs\u2026",
  get_csr_info: "Loading CSR\u2026",
  create_csr: "Creating CSR\u2026",
  sign_csr: "Signing CSR\u2026",
  import_csr_cert: "Importing CSR certificate\u2026",
  decode_csr: "Decoding CSR\u2026",

  // DKIM
  list_dkim_keys: "Loading DKIM keys\u2026",
  get_dkim_info: "Loading DKIM info\u2026",
  create_dkim_key: "Creating DKIM key\u2026",
  delete_dkim_key: "Deleting DKIM key\u2026",
  verify_dkim_dns: "Verifying DKIM DNS\u2026",
  deploy_dkim_route53: "Deploying DKIM to Route53\u2026",

  // OpenVPN
  get_openvpn_params: "Loading OpenVPN params\u2026",
  generate_openvpn_dh: "Generating DH parameters\u2026",
  generate_openvpn_ta: "Generating TLS auth key\u2026",
  setup_openvpn_server: "Setting up OpenVPN server\u2026",
  list_openvpn_templates: "Loading templates\u2026",
  get_openvpn_template: "Loading template\u2026",
  save_openvpn_template: "Saving template\u2026",
  list_vpn_clients: "Loading VPN clients\u2026",
  generate_openvpn_profile: "Generating VPN profile\u2026",
  list_openvpn_profiles: "Loading VPN profiles\u2026",
  send_profile_to_vault: "Sending profile to vault\u2026",

  // Database
  get_database_info: "Loading database info\u2026",
  get_action_log: "Loading action log\u2026",

  // Vault backup/restore
  vault_backup: "Creating backup\u2026",
  vault_restore: "Restoring from backup\u2026",
  vault_info: "Reading backup info\u2026",
  vault_default_filename: "Preparing backup\u2026",
  generate_password: "Generating password\u2026",
  store_password_in_op: "Storing password in 1Password\u2026",

  // Background (emitted via Tauri event)
  store_database: "Saving database\u2026",
};

/** Commands that should not update the status indicator. */
const hiddenOps = new Set([
  "acquire_lock",
  "release_lock",
  "read_text_file",
  "check_for_updates",
  "check_op_cli",
]);

const [activeOperation, setActiveOperation] = createSignal<string | null>(null);

/** Human-readable label for the currently active operation, or null when idle. */
export function operationLabel(): string | null {
  const op = activeOperation();
  if (!op) return null;
  return operationLabels[op] ?? op;
}

/** Whether a command should update the status indicator. */
export function isVisibleOp(cmd: string): boolean {
  return !hiddenOps.has(cmd);
}

/** Start listening for background operation events from Rust. */
export async function initOperationListener(): Promise<void> {
  await listen<string | null>("op-status", (event) => {
    setActiveOperation(event.payload);
  });
}

export { activeOperation, setActiveOperation };
