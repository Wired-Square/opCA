import { createEffect, createSignal, on } from "solid-js";
import { syncBrokers } from "../api/brokers";

const [brokersSynced, setBrokersSynced] = createSignal(0);

/** Bumped each time a background sync of the brokers lands. */
export { brokersSynced };

/** Runs `refetch` whenever a background sync lands, for a page showing the brokers. */
export const onBrokersSynced = (refetch: () => void) =>
  createEffect(on(brokersSynced, () => refetch(), { defer: true }));

/** Syncs the brokers without anyone waiting on it; a held lock or a failure only skips it. */
export function syncBrokersInBackground() {
  syncBrokers().then(
    () => setBrokersSynced((n) => n + 1),
    (e) => console.warn("Syncing the ACME servers was skipped:", e),
  );
}
