import { tauriInvoke, withLock } from "./tauri";
import type {
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

export async function brokerStatus(id: number): Promise<BrokerStatus> {
  return withLock("broker_status", () => tauriInvoke<BrokerStatus>("broker_status", { id }));
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

export function concernText(c: Concern): string {
  switch (c.concern) {
    case "expiring":
      return c.days < 0 ? `expired ${-c.days} days ago` : `expires in ${c.days} days`;
    case "silent":
      return `not heard from in ${c.days} days`;
    case "not_delivered":
      return "signed, not delivered";
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
