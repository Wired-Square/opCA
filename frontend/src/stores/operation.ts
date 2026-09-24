import { createSignal } from "solid-js";
import { listen } from "@tauri-apps/api/event";

/** Human-readable labels for Tauri command names. */
const operationLabels: Record<string, string> = {
  // Connect
  connect: "Connecting to vault\u2026",
  disconnect: "Disconnecting\u2026",
  list_vaults: "Listing vaults\u2026",
  list_accounts: "Listing accounts\u2026",
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
  delete_cert: "Deleting certificate\u2026",
  renew_cert: "Renewing certificate\u2026",
  rekey_cert: "Rekeying certificate\u2026",
  ignore_cert: "Marking certificate ignored\u2026",
  unignore_cert: "Clearing certificate ignore\u2026",
  import_cert: "Importing certificate\u2026",
  // Bulk operations \u2014 these are the base labels; once the batch starts, a
  // `bulk-progress` event overrides them with a live "{verb} {n}/{total}".
  bulk_rekey_certs: "Rekeying certificates\u2026",
  bulk_renew_certs: "Renewing certificates\u2026",
  bulk_revoke_certs: "Revoking certificates\u2026",
  bulk_delete_certs: "Deleting certificates\u2026",
  bulk_ignore_certs: "Ignoring certificates\u2026",
  bulk_unignore_certs: "Clearing ignores\u2026",

  // CRL
  get_crl_info: "Loading CRL\u2026",
  generate_crl: "Generating CRL\u2026",
  upload_crl: "Uploading CRL\u2026",

  // CSR
  list_csrs: "Loading CSRs\u2026",
  get_csr_info: "Loading CSR\u2026",
  create_csr: "Creating CSR\u2026",
  delete_csr: "Deleting CSR\u2026",
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
  sync_openvpn_templates: "Syncing templates\u2026",
  get_openvpn_template: "Loading template\u2026",
  save_openvpn_template: "Saving template\u2026",
  list_vpn_certs: "Loading VPN certificates\u2026",
  generate_openvpn_profile: "Generating VPN profile\u2026",
  bulk_generate_openvpn_profiles: "Regenerating VPN profiles\u2026",
  add_openvpn_profile_entries: "Adding VPN profiles\u2026",
  list_openvpn_profiles: "Loading VPN profiles\u2026",
  delete_openvpn_profile: "Deleting VPN profile\u2026",
  bulk_delete_openvpn_profiles: "Deleting VPN profiles\u2026",
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

  // Locking \u2014 acquire/release each write to 1Password (slow), so they get
  // visible labels: "Acquiring lock\u2026" gives feedback before the operation runs,
  // "Releasing lock\u2026" fills the trailing pause after it completes.
  acquire_lock: "Acquiring lock\u2026",
  release_lock: "Releasing lock\u2026",

  // Background (emitted via Tauri event)
  store_database: "Saving database\u2026",
  sync_private_store: "Syncing backup\u2026",
};

/** Commands that should not update the status indicator. */
const hiddenOps = new Set([
  "read_text_file",
  "check_for_updates",
  "check_op_cli",
]);

// Operations currently in flight, most-recent last. The indicator shows the top
// of the stack, so it never blanks while work is ongoing and a finishing
// background task (which emits `op-status: null`) can't clear a foreground op
// that's still running — it only removes its own entry.
const stack: string[] = [];
const [activeOperation, setActiveOperation] = createSignal<string | null>(null);

// Live per-item progress for a bulk command (e.g. "Rekeying 3/7…"). It overrides
// the static label, but only while its originating command is the active op — so
// it can't bleed into the trailing release_lock / sync once the batch finishes.
const [progressDetail, setProgressDetail] = createSignal<string | null>(null);
let progressFor: string | null = null;

function refresh() {
  setActiveOperation(stack.length > 0 ? stack[stack.length - 1] : null);
}

/** Mark an operation as started. */
export function beginOp(cmd: string): void {
  stack.push(cmd);
  refresh();
}

/** Mark an operation as finished (removes its most recent entry). */
export function endOp(cmd: string): void {
  const i = stack.lastIndexOf(cmd);
  if (i !== -1) stack.splice(i, 1);
  if (cmd === progressFor) {
    progressFor = null;
    setProgressDetail(null);
  }
  refresh();
}

/** Human-readable label for the currently active operation, or null when idle. */
export function operationLabel(): string | null {
  const op = activeOperation();
  if (!op) return null;
  if (progressFor === op && progressDetail()) return progressDetail();
  return operationLabels[op] ?? op;
}

/** Whether a command should update the status indicator. */
export function isVisibleOp(cmd: string): boolean {
  return !hiddenOps.has(cmd);
}

/** Start listening for background operation events from Rust. Each task brackets
 * its work with `op-status: Some(name)` … `op-status: null`; we track them on a
 * parallel stack so an unnamed end pops the right entry. */
export async function initOperationListener(): Promise<void> {
  const bgStack: string[] = [];
  await listen<string | null>("op-status", (event) => {
    if (event.payload) {
      bgStack.push(event.payload);
      beginOp(event.payload);
    } else {
      const op = bgStack.pop();
      if (op) endOp(op);
    }
  });

  // Live progress for bulk commands: attach the "{verb} {n}/{total}" detail to
  // whichever command is currently running (it's cleared when that op ends).
  await listen<{ verb: string; current: number; total: number }>("bulk-progress", (event) => {
    const { verb, current, total } = event.payload;
    progressFor = activeOperation();
    setProgressDetail(`${verb} ${current}/${total}…`);
  });
}

export { activeOperation, setActiveOperation };
