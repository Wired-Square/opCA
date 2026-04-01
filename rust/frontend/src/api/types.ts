// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

export interface DashboardData {
  ca_valid: boolean;
  ca_cn: string | null;
  ca_expiry: string | null;
  total_certs: number;
  valid_certs: number;
  expired_certs: number;
  expiring_certs: number;
  revoked_certs: number;
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
  cn?: string;
}

// ---------------------------------------------------------------------------
// DKIM
// ---------------------------------------------------------------------------

export interface DkimKeyItem {
  domain: string;
  selector: string;
  created_at: string | null;
}

export interface DkimKeyDetail {
  domain: string;
  selector: string;
  key_size: string | null;
  dns_name: string;
  dns_record: string | null;
  created_at: string | null;
  public_key: string | null;
}

export interface CreateDkimRequest {
  domain: string;
  selector: string;
  key_size?: number;
}

export interface CreateDkimResult {
  item: DkimKeyItem;
  dns_name: string;
  dns_record: string;
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
