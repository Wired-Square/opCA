// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

export type CaExpiryLevel = "critical" | "prominent" | "cert_lifetime" | "none";
export type CrlExpiryLevel = "critical" | "prominent" | "expired" | "none";
export type ActionSeverity = "critical" | "warning" | "info";
export type ActionKind =
  | "regenerate_and_upload_crl"
  | "regenerate_crl"
  | "view_expired_certs"
  | "view_pending_csrs"
  | "view_ca";

export interface CaExpiryWarning {
  level: CaExpiryLevel;
  days_remaining: number | null;
  message: string;
}

export interface CrlExpiryWarning {
  level: CrlExpiryLevel;
  days_remaining: number | null;
  message: string;
}

export interface ActionItem {
  id: string;
  severity: ActionSeverity;
  message: string;
  button_label: string;
  action: ActionKind;
}

export interface DashboardData {
  ca_valid: boolean;
  ca_cn: string | null;
  ca_expiry: string | null;
  ca_expiry_warning: CaExpiryWarning | null;
  crl_present: boolean;
  crl_next_update: string | null;
  crl_expiry_warning: CrlExpiryWarning | null;
  total_certs: number;
  valid_certs: number;
  expired_certs: number;
  expiring_certs: number;
  warning_certs: number;
  revoked_certs: number;
  pending_csrs: number;
  has_public_store: boolean;
  action_items: ActionItem[];
}

// ---------------------------------------------------------------------------
// CA
// ---------------------------------------------------------------------------

export interface CaInfo {
  cn: string | null;
  subject: string | null;
  issuer: string | null;
  serial: string | null;
  not_before: string | null;
  not_after: string | null;
  key_type: string | null;
  key_size: string | null;
  is_valid: boolean;
  cert_pem: string | null;
  /** `true` if the CA private key is loaded into the in-memory bundle.
   * Always true for an initialised CA, but the UI reads it explicitly
   * for the Stored Items indicator. */
  has_private_key: boolean;
}

export interface CaConfig {
  next_serial: number | null;
  next_crl_serial: number | null;
  org: string | null;
  ou: string | null;
  email: string | null;
  city: string | null;
  state: string | null;
  country: string | null;
  ca_url: string | null;
  crl_url: string | null;
  days: number | null;
  crl_days: number | null;
  ca_public_store: string | null;
  ca_private_store: string | null;
  ca_backup_store: string | null;
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

export const CERT_TYPES = [
  { value: "device", label: "Device" },
  { value: "webserver", label: "Web Server" },
  { value: "vpnclient", label: "VPN Client" },
  { value: "vpnserver", label: "VPN Server" },
] as const;

export interface CertListItem {
  serial: string | null;
  cn: string | null;
  title: string | null;
  status: string | null;
  cert_type: string | null;
  expiry_date: string | null;
  key_type: string | null;
  key_size: number | null;
  /** Presence indicates the cert is ignored; value is the timestamp. */
  ignored_at: string | null;
  /** If expired and a same-CN Valid replacement exists, its serial. */
  superseded_by: string | null;
  /** Still-Valid but inside the expiry-warning window — shown as "Expiring Soon". */
  expiring_soon: boolean;
}

export interface ExternalCertListItem {
  serial: string | null;
  cn: string | null;
  status: string | null;
  cert_type: string | null;
  expiry_date: string | null;
  issuer: string | null;
  import_date: string | null;
  key_type: string | null;
  key_size: number | null;
}

export interface CertDetail extends CertListItem {
  subject: string | null;
  issuer: string | null;
  not_before: string | null;
  revocation_date: string | null;
  san: string | null;
  cert_pem: string | null;
  /** `username@hostname` of the user who set the ignore. */
  ignored_by: string | null;
  /** Typically `manual` for new ignores; legacy rows may carry other strings. */
  ignored_reason: string | null;
  /** Optional free-text note. */
  ignored_note: string | null;
  /** Whether a private key is stored alongside the cert in 1Password.
   * `null` for legacy rows that pre-date the v9 schema; populated by the
   * detail page's backfill the first time it's opened. */
  has_private_key: boolean | null;
  /** Whether an issuer chain is stored alongside the cert in 1Password. */
  has_chain: boolean | null;
  /** PEM-encoded issuer chain — populated by the slow backfill path. */
  chain_pem: string | null;
}

/** Result of a renew or rekey — the new cert lives at a new serial. */
export interface RenewRekeyResult {
  serial: string;
  pem: string;
}

export interface ExternalCertDetail {
  serial: string | null;
  cn: string | null;
  title: string | null;
  status: string | null;
  cert_type: string | null;
  expiry_date: string | null;
  key_type: string | null;
  key_size: number | null;
  subject: string | null;
  issuer: string | null;
  issuer_subject: string | null;
  not_before: string | null;
  import_date: string | null;
  san: string | null;
  cert_pem: string | null;
  has_private_key: boolean | null;
  has_chain: boolean | null;
  chain_pem: string | null;
}

export interface CreateCertRequest {
  cn: string;
  cert_type: string;
  alt_dns_names?: string[];
  key_size?: number;
}

export interface ImportCertRequest {
  cert_pem: string;
  key_pem?: string;
  passphrase?: string;
  chain_pem?: string;
}

export interface ImportCertResult {
  cert: CertListItem;
  is_external: boolean;
}

export interface InspectCertificateResult {
  cn: string | null;
  subject: string;
  issuer: string;
  serial: string | null;
  not_before: string | null;
  not_after: string | null;
  alt_dns_names: string[];
  key_type: string;
  key_size: number;
  signature_algorithm: string;
  public_key_fingerprint_sha256: string;
  is_ca: boolean;
  text_dump: string;
}

// ---------------------------------------------------------------------------
// CSR
// ---------------------------------------------------------------------------

export interface CsrListItem {
  id: number | null;
  cn: string | null;
  title: string | null;
  csr_type: string | null;
  email: string | null;
  subject: string | null;
  status: string | null;
  created_date: string | null;
}

export interface DecodeCsrResult {
  cn: string | null;
  subject: string;
  alt_dns_names: string[];
}

export interface CreateCsrRequest {
  cn: string;
  csr_type: string;
  email?: string;
  country?: string;
  key_size?: number;
  alt_dns_names?: string[];
}

export interface CreateCsrResult {
  item: CsrListItem;
  csr_pem: string;
}

export interface SignCsrRequest {
  csr_pem: string;
  csr_type: string;
  cn?: string;
}

export interface SignCsrResult {
  cert: CertListItem;
  cert_pem: string;
}

export interface ImportCsrCertRequest {
  cert_pem: string;
  chain_pem?: string;
  cn?: string;
}

export interface GenerateCsrFromCertRequest {
  serial: string;
}

export interface InspectCsrResult {
  cn: string | null;
  subject: string;
  alt_dns_names: string[];
  key_type: string;
  key_size: number;
  signature_algorithm: string;
  public_key_fingerprint_sha256: string;
  text_dump: string;
}

// ---------------------------------------------------------------------------
// DKIM
// ---------------------------------------------------------------------------

export interface DkimKeyItem {
  domain: string;
  selector: string;
  key_size: number | null;
  created_at: string | null;
}

export interface DkimKeyDetail {
  domain: string;
  selector: string;
  key_size: number | null;
  dns_name: string;
  dns_record: string | null;
  /** `dns_record` reformatted as 255-byte quoted chunks for AWS Route53. */
  dns_record_chunked: string | null;
  created_at: string | null;
  public_key: string | null;
  /** Stored Items flags — `null` until the slow-path backfill confirms. */
  has_private_key: boolean | null;
  has_public_key: boolean | null;
  has_dns_record: boolean | null;
  /** `true` if the stored private key derives a public key matching the
   * stored public key. `null` until the slow-path verification runs. */
  key_pair_match: boolean | null;
}

export type DkimCopyKind = "selector" | "public_key" | "dns_record";

export interface CreateDkimRequest {
  domain: string;
  selector: string;
  key_size?: number;
}

export interface CreateDkimResult {
  item: DkimKeyItem;
  dns_name: string;
  dns_record: string;
  /** `dns_record` reformatted as 255-byte quoted chunks for AWS Route53. */
  dns_record_chunked: string;
}

export interface DkimVerifyResult {
  verified: boolean;
  dns_name: string;
  message: string;
  expected?: string;
  found?: string;
}

export interface DkimRoute53Result {
  dns_name: string;
  zone_name: string;
  message: string;
}

// ---------------------------------------------------------------------------
// OpenVPN
// ---------------------------------------------------------------------------

export interface OpenVpnServerParams {
  has_item: boolean;
  dh_key_size: string | null;
  has_dh: boolean;
  ta_key_size: string | null;
  has_ta: boolean;
  hostname: string | null;
  port: string | null;
  cipher: string | null;
  auth: string | null;
}

export interface OpenVpnTemplateItem {
  name: string;
  updated_date: string | null;
}

export interface OpenVpnTemplateDetail {
  name: string;
  content: string;
  updated_date: string | null;
}

export interface OpenVpnProfileItem {
  cn: string;
  title: string;
  created_date: string | null;
  template: string | null;
}

export interface GenerateProfileRequest {
  cn: string;
  template_name: string;
  dest_vault?: string;
}

export interface ServerSetupRequest {
  template_name: string;
}

// ---------------------------------------------------------------------------
// Store Testing
// ---------------------------------------------------------------------------

/** Maps store name ("public" | "private" | "backup") to "ok" or error message. */
export type StoreTestResults = Record<string, string>;

// ---------------------------------------------------------------------------
// CRL
// ---------------------------------------------------------------------------

export interface CrlInfo {
  issuer: string | null;
  last_update: string | null;
  next_update: string | null;
  crl_number: number | null;
  revoked_count: number;
  crl_pem: string | null;
  has_public_store: boolean;
  /** `true` once the slow backfill has confirmed the CRL exists in
   * 1Password. `null` on the fast path. */
  has_crl: boolean | null;
}

export interface InspectCrlResult {
  issuer: string;
  last_update: string | null;
  next_update: string | null;
  crl_number: number | null;
  revoked_count: number;
  signature_algorithm: string;
  text_dump: string;
}

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

export interface DatabaseInfo {
  config: CaConfig;
  total_certs: number;
  total_external_certs: number;
  schema_version: number;
}

// ---------------------------------------------------------------------------
// Action Log
// ---------------------------------------------------------------------------

export interface LogEntry {
  timestamp: number;
  action: string;
  detail: string | null;
  success: boolean;
}

// ---------------------------------------------------------------------------
// Vault Backup
// ---------------------------------------------------------------------------

export interface BackupInfoResult {
  opca_version: string;
  vault_name: string;
  backup_date: string;
  item_count: number;
  item_breakdown: BackupItemCount[];
}

export interface BackupItemCount {
  item_type: string;
  count: number;
}

export interface RestoreResult {
  items_restored: number;
  item_breakdown: BackupItemCount[];
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

export interface UpdateInfo {
  version: string;
  url: string;
}

// ---------------------------------------------------------------------------
// Vaults
// ---------------------------------------------------------------------------

export interface VaultInfo {
  id: string;
  name: string;
}

// ---------------------------------------------------------------------------
// Connection (existing, centralised here)
// ---------------------------------------------------------------------------

export interface ConnectionInfo {
  connected: boolean;
  vault: string;
  account: string | null;
  vault_state: string;
}
