import { Show, Switch, Match } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { invoke } from "@tauri-apps/api/core";
import { appState, setAppState } from "../../stores/app";
import { themeMode, toggleTheme } from "../../stores/theme";
import Icon from "../Icon";
import "../../styles/components/header.css";

export default function Header() {
  const navigate = useNavigate();

  async function handleLogout() {
    await invoke("disconnect");
    setAppState({
      connected: false,
      vaultState: "disconnected",
      vault: "",
      account: null,
    });
    navigate("/");
  }

  return (
    <header class="app-header">
      <div class="header-info">
        <Show when={appState.connected}>
          <span class="header-vault">
            <span class="header-label">Vault:</span>
            <span class="header-value">{appState.vault}</span>
          </span>
          <Show when={appState.account}>
            <span class="header-account">
              <span class="header-label">Account:</span>
              <span class="header-value">{appState.account}</span>
            </span>
          </Show>
          <Switch>
            <Match when={appState.vaultState === "valid_ca"}>
              <span class="header-badge header-badge-valid">valid CA</span>
            </Match>
            <Match when={appState.vaultState === "empty_vault"}>
              <span class="header-badge header-badge-warning">empty vault</span>
            </Match>
            <Match when={appState.vaultState === "invalid_ca"}>
              <span class="header-badge header-badge-error">invalid CA</span>
            </Match>
          </Switch>
        </Show>
      </div>
      <div class="header-actions">
        <button class="btn-ghost theme-toggle" onClick={toggleTheme} aria-label="Toggle theme" title="Toggle theme">
          {themeMode() === "dark" ? "\u2600" : "\u263E"}
        </button>
        <button class="btn-ghost disconnect-btn" onClick={handleLogout} aria-label="Disconnect" title="Disconnect">
          <Icon name="logout" />
        </button>
      </div>
    </header>
  );
}
