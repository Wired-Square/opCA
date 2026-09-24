import { createStore } from "solid-js/store";
import { tauriInvoke } from "../api/tauri";

export type VaultState = "disconnected" | "valid_ca" | "empty_vault" | "invalid_ca";

export interface AppStore {
  connected: boolean;
  vaultState: VaultState;
  vault: string;
  account: string | null;
  loading: boolean;
}

const [appState, setAppState] = createStore<AppStore>({
  connected: false,
  vaultState: "disconnected",
  vault: "",
  account: null,
  loading: false,
});

/** Convenience: true when the vault contains a valid CA. */
export const hasCA = () => appState.vaultState === "valid_ca";

/** Releases the vault lock and connection in the backend, then forgets them here. */
export async function disconnect() {
  await tauriInvoke("disconnect");
  setAppState({
    connected: false,
    vaultState: "disconnected",
    vault: "",
    account: null,
  });
}

export { appState, setAppState };
