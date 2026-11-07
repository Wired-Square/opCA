import { tauriInvoke, withLock } from "./tauri";
import type {
  BrokerCert,
  BrokerError,
  BrokerOffer,
  BrokerRenewal,
  BrokerRevocation,
  BrokerRow,
  BrokerStatus,
  Concern,
  EnrolledBroker,
  EnrolmentOffer,
  Renewal,
} from "./types";

export async function fetchBrokerOffer(pairing: string): Promise<BrokerOffer> {
  return tauriInvoke<BrokerOffer>("fetch_broker_offer", { pairing });
}

export async function enrolBroker(request: {
  pairing: string;
  offer: EnrolmentOffer;
  domains: string[];
}): Promise<EnrolledBroker> {
  return withLock("enrol_broker", () => tauriInvoke<EnrolledBroker>("enrol_broker", { request }));
}

export async function listBrokers(): Promise<BrokerRow[]> {
  return tauriInvoke<BrokerRow[]>("list_brokers");
}

export async function listBrokerCerts(): Promise<BrokerCert[]> {
  return tauriInvoke<BrokerCert[]>("list_broker_certs");
}

export async function brokerStatus(id: number): Promise<BrokerStatus> {
  return withLock("broker_status", () => tauriInvoke<BrokerStatus>("broker_status", { id }));
}

/** Asks every active broker for its status and what it issued, as Status does for one. */
export async function syncBrokers(): Promise<void> {
  return withLock("sync_brokers", () => tauriInvoke<void>("sync_brokers"));
}

export async function renewBroker(id: number, changeDomains = false): Promise<Renewal> {
  return withLock("renew_broker", () => tauriInvoke<Renewal>("renew_broker", { id, changeDomains }));
}

export async function renewAllBrokers(): Promise<BrokerRenewal[]> {
  return withLock("renew_all_brokers", () => tauriInvoke<BrokerRenewal[]>("renew_all_brokers"));
}

export async function revokeBroker(id: number): Promise<BrokerRevocation> {
  return withLock("revoke_broker", () => tauriInvoke<BrokerRevocation>("revoke_broker", { id }));
}

export async function pauseBroker(id: number, paused: boolean): Promise<BrokerStatus> {
  return withLock("pause_broker", () => tauriInvoke<BrokerStatus>("pause_broker", { id, paused }));
}

export async function revokeBrokerCert(id: number, serial: string, reason: number): Promise<BrokerCert> {
  return withLock("revoke_broker_cert", () =>
    tauriInvoke<BrokerCert>("revoke_broker_cert", { id, serial, reason }),
  );
}

/** The RFC 5280 CRLReasons a broker takes for a leaf, named as the broker's page names them. */
export const REVOCATION_REASONS: [number, string][] = [
  [0, "unspecified"],
  [1, "key compromise"],
  [2, "CA compromise"],
  [3, "affiliation changed"],
  [4, "superseded"],
  [5, "cessation of operation"],
  [6, "certificate hold"],
  [9, "privilege withdrawn"],
  [10, "AA compromise"],
];

export const expiryText = (days: number) => (days < 0 ? `expired ${-days} days ago` : `expires in ${days} days`);

export function concernText(c: Concern): string {
  switch (c.concern) {
    case "expiring":
      return expiryText(c.days);
    case "silent":
      return `not heard from in ${c.days} days`;
    case "not_delivered":
      return "signed, not delivered";
    case "paused":
      return "issuance paused";
  }
}

export function brokerErrorText(e: BrokerError): string {
  return e.kind === "status" ? `the broker answered HTTP ${e.status}` : e.message;
}

export function renewalText(r: Renewal): string {
  switch (r.outcome) {
    case "renewed":
      return `Renewed (serial ${r.serial})`;
    case "domains_changed":
      return `Now asks for ${r.configured.join(", ")} instead of ${r.recorded.join(", ")}; nothing was signed`;
    case "unreachable":
      return `Unreachable: ${brokerErrorText(r.error)}`;
    case "not_delivered":
      return `Signed (serial ${r.serial}) but not delivered: ${brokerErrorText(r.error)}. Renew again to sign afresh.`;
    case "failed":
      return `Failed: ${r.error}`;
  }
}

/** The domains typed one per line, or separated by spaces or commas. */
export const domainList = (text: string) => text.split(/[\s,]+/).filter(Boolean);
