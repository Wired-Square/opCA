import { createSignal } from "solid-js";
import { checkForUpdates } from "../api/update";
import type { UpdateInfo } from "../api/types";

const [availableUpdate, setAvailableUpdate] = createSignal<UpdateInfo | null>(null);

/** Fire-and-forget update check — errors are silently ignored. */
async function fetchUpdate() {
  try {
    setAvailableUpdate(await checkForUpdates());
  } catch {
    // Silently fail — update checking is best-effort
  }
}

export { availableUpdate, fetchUpdate };
