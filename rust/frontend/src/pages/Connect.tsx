import { createSignal, Show, For, onMount } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-shell";
import { setAppState, type VaultState } from "../stores/app";
import { themeMode, toggleTheme } from "../stores/theme";
import { availableUpdate, fetchUpdate } from "../stores/update";
import "../styles/pages/connect.css";

interface ConnectionInfo {
  connected: boolean;
  vault: string;
  account: string | null;
  vault_state: string;
}

interface OpCliStatus {
  found: boolean;
  path: string | null;
}

interface SavedLogin {
  vault: string;
  account: string | null;
}

const STORAGE_KEY = "opca_saved_logins";

function loadSavedLogins(): SavedLogin[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function persistLogins(logins: SavedLogin[]) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(logins));
}

function addLogin(vault: string, account: string | null): SavedLogin[] {
  const logins = loadSavedLogins().filter(
    (l) => !(l.vault === vault && l.account === account),
  );
  logins.unshift({ vault, account });
  persistLogins(logins);
  return logins;
}

function removeLogin(vault: string, account: string | null): SavedLogin[] {
  const logins = loadSavedLogins().filter(
    (l) => !(l.vault === vault && l.account === account),
  );
  persistLogins(logins);
  return logins;
}

const updateIcon = `<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="8"/><polyline points="8 12 12 8 16 12"/></svg>`;

export default function Connect() {
  const navigate = useNavigate();
  const [vault, setVault] = createSignal("");
  const [account, setAccount] = createSignal("");
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [saved, setSaved] = createSignal<SavedLogin[]>([]);
  const [dropdownOpen, setDropdownOpen] = createSignal(false);
  const [opCli, setOpCli] = createSignal<OpCliStatus | null>(null);

  onMount(async () => {
    setSaved(loadSavedLogins());
    try {
      const status = await invoke<OpCliStatus>("check_op_cli");
      setOpCli(status);
    } catch {
      setOpCli({ found: false, path: null });
    }
    fetchUpdate();
  });

  function selectLogin(login: SavedLogin) {
    setVault(login.vault);
    setAccount(login.account ?? "");
    setDropdownOpen(false);
  }

  function forgetLogin(e: Event, login: SavedLogin) {
    e.stopPropagation();
    setSaved(removeLogin(login.vault, login.account));
  }

  async function handleConnect(e: Event) {
    e.preventDefault();
    if (!vault().trim()) return;

    setLoading(true);
    setError(null);

    try {
      const info = await invoke<ConnectionInfo>("connect", {
        vault: vault(),
        account: account() || null,
      });
      setAppState({
        connected: info.connected,
        vault: info.vault,
        account: info.account,
        vaultState: info.vault_state as VaultState,
      });
      setSaved(addLogin(info.vault, info.account));
      navigate("/dashboard");
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div class="connect-page" onClick={() => setDropdownOpen(false)}>
      <div class="connect-card">
        <div class="connect-header">
          <div class="connect-brand-row">
            <img src="/logo.svg" alt="" class="connect-logo" />
            <h1 class="connect-title">
              <span class="brand-op">op</span>
              <span class="brand-ca">CA</span>
            </h1>
          </div>
          <p class="connect-subtitle">Certificate Authority Manager</p>
          <p class="connect-byline">by Wired Square</p>
        </div>

        <form class="connect-form" onSubmit={handleConnect}>
          <div class="form-group">
            <label class="form-label" for="vault">1Password Vault</label>
            <div class="input-with-dropdown" onClick={(e) => e.stopPropagation()}>
              <input
                id="vault"
                type="text"
                placeholder="e.g. Private CA"
                value={vault()}
                onInput={(e) => {
                  setVault(e.currentTarget.value);
                  setDropdownOpen(false);
                }}
                onFocus={() => saved().length > 0 && setDropdownOpen(true)}
                autofocus
                autocomplete="off"
                autocorrect="off"
                autocapitalize="off"
                spellcheck={false}
              />
              <Show when={saved().length > 0}>
                <button
                  type="button"
                  class="dropdown-toggle"
                  aria-label="Show saved vaults"
                  onClick={() => setDropdownOpen(!dropdownOpen())}
                  tabIndex={-1}
                >
{"\u21BB"}
                </button>
              </Show>
              <Show when={dropdownOpen() && saved().length > 0}>
                <div class="saved-dropdown">
                  <For each={saved()}>
                    {(login) => (
                      <div class="saved-item" onClick={() => selectLogin(login)}>
                        <div class="saved-item-info">
                          <span class="saved-vault">{login.vault}</span>
                          <Show when={login.account}>
                            <span class="saved-account">{login.account}</span>
                          </Show>
                        </div>
                        <button
                          type="button"
                          class="saved-forget"
                          aria-label="Forget this login"
                          onClick={(e) => forgetLogin(e, login)}
                          title="Forget this login"
                        >
                          &times;
                        </button>
                      </div>
                    )}
                  </For>
                </div>
              </Show>
            </div>
          </div>

          <div class="form-group">
            <label class="form-label" for="account">Account (optional)</label>
            <input
              id="account"
              type="text"
              placeholder="e.g. my.1password.com"
              value={account()}
              onInput={(e) => {
                setAccount(e.currentTarget.value);
                setDropdownOpen(false);
              }}
              autocomplete="off"
              autocorrect="off"
              autocapitalize="off"
              spellcheck={false}
            />
          </div>

          {error() && <p class="connect-error" role="alert">{error()}</p>}

          <button class="btn-primary connect-btn" type="submit" disabled={loading() || !vault().trim()}>
            {loading() ? "Connecting\u2026" : "Connect"}
          </button>
        </form>

        <button class="btn-ghost theme-toggle-connect" onClick={toggleTheme} title="Toggle theme">
          {themeMode() === "dark" ? "\u2600 Light mode" : "\u263E Dark mode"}
        </button>

        <Show when={opCli()}>
          {(status) => (
            <div class={`op-cli-status ${status().found ? "op-cli-found" : "op-cli-missing"}`}>
              <span class="op-cli-dot" />
              <span class="op-cli-text">
                {status().found ? `op CLI found: ${status().path}` : "op CLI not found on PATH"}
              </span>
            </div>
          )}
        </Show>

        <Show when={availableUpdate()}>
          {(update) => (
            <button
              class="connect-update-badge"
              onClick={() => open(update().url)}
              title={`Update available: ${update().version}`}
            >
              <span class="connect-update-icon" innerHTML={updateIcon} />
              Update available: {update().version}
            </button>
          )}
        </Show>
      </div>

    </div>
  );
}
