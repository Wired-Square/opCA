import { createSignal } from "solid-js";
import { listen } from "@tauri-apps/api/event";

/** Set when a quit is being held until an in-flight 1Password operation finishes. */
const [quitPending, setQuitPending] = createSignal(false);

export { quitPending };

export async function initQuitListener(): Promise<void> {
  await listen("quit-pending", () => setQuitPending(true));
}
