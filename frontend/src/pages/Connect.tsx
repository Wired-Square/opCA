import { createSignal, Show, For, onMount, type JSX } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-shell";
import { listAccounts, accountValue, accountLabel } from "../api/accounts";
import { createVault } from "../api/vaults";
import type { AccountInfo } from "../api/types";
import { setAppState, type VaultState } from "../stores/app";
import { themeMode, toggleTheme } from "../stores/theme";
import { availableUpdate, fetchUpdate } from "../stores/update";
import Icon from "../components/Icon";
import Popover, { PopoverOption } from "../components/Popover";
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

/** Which field's dropdown is open — only ever one at a time. */
type Dropdown = "vault" | "account";

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

/** A labelled text field with an in-field button that drops a list of choices
 *  below it. Both fields on this page are this shape; `children` are the rows.
 *  The button is hidden when there is nothing to offer. */
function PickerField(props: {
  id: string;
  label: string;
  placeholder: string;
  value: string;
  onInput: (value: string) => void;
  onFocus?: () => void;
  autofocus?: boolean;
  /** Toggle glyph and its accessible name; omit to offer no dropdown. */
  toggle?: { glyph: string; label: string };
  open: boolean;
  onToggle: () => void;
  onClose: () => void;
  children: JSX.Element;
}) {
  let fieldEl!: HTMLDivElement;
  return (
    <div class="form-group">
      <label class="form-label" for={props.id}>{props.label}</label>
      <div ref={fieldEl} class="input-with-dropdown">
        <input
          id={props.id}
          type="text"
          placeholder={props.placeholder}
          value={props.value}
          onInput={(e) => props.onInput(e.currentTarget.value)}
          onFocus={() => props.onFocus?.()}
          autofocus={props.autofocus}
          autocomplete="off"
          autocorrect="off"
          autocapitalize="off"
          spellcheck={false}
        />
        <Show when={props.toggle}>
          {(toggle) => (
            <button
              type="button"
              class="dropdown-toggle"
              aria-label={toggle().label}
              aria-haspopup="listbox"
              aria-expanded={props.open}
              onClick={props.onToggle}
              tabIndex={-1}
            >
              {toggle().glyph}
            </button>
          )}
        </Show>
        {/* Gated on `toggle` as well as `open`, so forgetting the last saved
            login closes the menu instead of leaving an empty box behind. */}
        <Show when={props.open && props.toggle}>
          <Popover anchor={fieldEl} matchWidth role="listbox" onClose={props.onClose}>
            {props.children}
          </Popover>
        </Show>
      </div>
    </div>
  );
}

/** One row of either dropdown: a primary line with a smaller one beneath, and
 *  an optional trailing button. */
function DropdownItem(props: {
  primary: string;
  secondary?: string | null;
  onSelect: () => void;
  children?: JSX.Element;
}) {
  return (
    <PopoverOption class="dropdown-item" onSelect={props.onSelect}>
      <div class="dropdown-item-lines">
        <span class="dropdown-item-primary">{props.primary}</span>
        <Show when={props.secondary}>
          <span class="dropdown-item-secondary">{props.secondary}</span>
        </Show>
      </div>
      {props.children}
    </PopoverOption>
  );
}

export default function Connect() {
  const navigate = useNavigate();
  const [vault, setVault] = createSignal("");
  const [account, setAccount] = createSignal("");
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [saved, setSaved] = createSignal<SavedLogin[]>([]);
  const [accounts, setAccounts] = createSignal<AccountInfo[]>([]);
  const [openDropdown, setOpenDropdown] = createSignal<Dropdown | null>(null);
  const [opCli, setOpCli] = createSignal<OpCliStatus | null>(null);
  const [creating, setCreating] = createSignal(false);

  onMount(async () => {
    setSaved(loadSavedLogins());
    fetchUpdate();
    // Both are local, sign-in-free lookups; neither gates the other. A failing
    // account list just leaves the picker hidden — the op CLI status line below
    // already reports the case where `op` is missing entirely.
    const [status, configured] = await Promise.all([
      invoke<OpCliStatus>("check_op_cli").catch(() => ({ found: false, path: null })),
      listAccounts().catch(() => []),
    ]);
    setOpCli(status);
    setAccounts(configured);
  });

  const toggle = (which: Dropdown) =>
    setOpenDropdown((current) => (current === which ? null : which));

  function selectLogin(login: SavedLogin) {
    setVault(login.vault);
    setAccount(login.account ?? "");
    setOpenDropdown(null);
  }

  function forgetLogin(e: Event, login: SavedLogin) {
    e.stopPropagation();
    setSaved(removeLogin(login.vault, login.account));
  }

  function selectAccount(picked: AccountInfo) {
    setAccount(accountValue(picked, accounts()));
    setOpenDropdown(null);
  }

  function switchMode() {
    setCreating(!creating());
    setOpenDropdown(null);
    setError(null);
  }

  async function handleSubmit(e: Event) {
    e.preventDefault();
    if (!vault().trim()) return;

    setLoading(true);
    setError(null);

    try {
      const name = creating()
        ? (await createVault(vault(), account() || null)).name
        : vault();
      const info = await invoke<ConnectionInfo>("connect", {
        vault: name,
        account: account() || null,
      });
      setAppState({
        connected: info.connected,
        vault: info.vault,
        account: info.account,
        vaultState: info.vault_state as VaultState,
      });
      setSaved(addLogin(info.vault, info.account));
      navigate(creating() ? "/ca" : "/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div class="connect-page">
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

        <form class="connect-form" onSubmit={handleSubmit}>
          <PickerField
            id="vault"
            label={creating() ? "New 1Password Vault" : "1Password Vault"}
            placeholder="e.g. Private CA"
            value={vault()}
            onInput={(v) => { setVault(v); setOpenDropdown(null); }}
            onFocus={() => !creating() && saved().length > 0 && setOpenDropdown("vault")}
            autofocus
            toggle={!creating() && saved().length > 0 ? { glyph: "↻", label: "Show saved vaults" } : undefined}
            open={openDropdown() === "vault"}
            onToggle={() => toggle("vault")}
            onClose={() => setOpenDropdown(null)}
          >
            <For each={saved()}>
              {(login) => (
                <DropdownItem
                  primary={login.vault}
                  secondary={accountLabel(login.account, accounts())}
                  onSelect={() => selectLogin(login)}
                >
                  <button
                    type="button"
                    class="saved-forget"
                    aria-label="Forget this login"
                    onClick={(e) => forgetLogin(e, login)}
                    title="Forget this login"
                  >
                    &times;
                  </button>
                </DropdownItem>
              )}
            </For>
          </PickerField>

          <PickerField
            id="account"
            label="Account (optional)"
            placeholder="e.g. my.1password.com"
            value={account()}
            onInput={(v) => { setAccount(v); setOpenDropdown(null); }}
            toggle={accounts().length > 0 ? { glyph: "▾", label: "Show 1Password accounts" } : undefined}
            open={openDropdown() === "account"}
            onToggle={() => toggle("account")}
            onClose={() => setOpenDropdown(null)}
          >
            <For each={accounts()}>
              {(configured) => (
                <DropdownItem
                  primary={configured.email}
                  secondary={configured.url}
                  onSelect={() => selectAccount(configured)}
                />
              )}
            </For>
          </PickerField>

          {error() && <p class="connect-error" role="alert">{error()}</p>}

          <button class="btn-primary connect-btn" type="submit" disabled={loading() || !vault().trim()}>
            {creating()
              ? loading() ? "Creating…" : "Create vault"
              : loading() ? "Connecting…" : "Connect"}
          </button>
        </form>

        <button class="btn-ghost connect-mode-switch" type="button" onClick={switchMode} disabled={loading()}>
          {creating() ? "Connect to an existing vault" : "New CA in a new vault…"}
        </button>

        <button class="btn-ghost theme-toggle-connect" onClick={toggleTheme} title="Toggle theme">
          {themeMode() === "dark" ? "☀ Light mode" : "☾ Dark mode"}
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
              <span class="connect-update-icon"><Icon name="update" /></span>
              Update available: {update().version}
            </button>
          )}
        </Show>
      </div>

    </div>
  );
}
