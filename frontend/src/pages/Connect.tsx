import { createResource, createSignal, Show, For, onMount, type JSX } from "solid-js";
import { errorMessage } from "../api/tauri";
import { useNavigate } from "@solidjs/router";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-shell";
import { listAccounts, accountValue, accountLabel } from "../api/accounts";
import { createVault, listVaults } from "../api/vaults";
import type { AccountInfo, VaultInfo } from "../api/types";
import { setAppState, type VaultState } from "../stores/app";
import { availableUpdate, fetchUpdate } from "../stores/update";
import Icon from "../components/Icon";
import Spinner from "../components/Spinner";
import { Popover, PopoverOption, SchemePicker } from "@wired-square/kit";
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

/** Which field's list is open — only ever one at a time. */
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

/** A labelled text field with a Browse button beside it that drops a list of
 *  choices below both; `children` are the rows. */
function PickerField(props: {
  id: string;
  label: string;
  placeholder: string;
  value: string;
  onInput: (value: string) => void;
  autofocus?: boolean;
  /** The Browse button's accessible name, and why it is disabled if it is; omit for no button. */
  browse?: { label: string; disabledReason?: string };
  heading: string;
  open: boolean;
  onToggle: () => void;
  onClose: () => void;
  children: JSX.Element;
}) {
  let fieldEl!: HTMLDivElement;
  const headingId = `${props.id}-list-heading`;
  return (
    <div class="form-group">
      <label class="form-label" for={props.id}>{props.label}</label>
      <div ref={fieldEl} class="picker-row">
        <input
          id={props.id}
          type="text"
          placeholder={props.placeholder}
          value={props.value}
          onInput={(e) => props.onInput(e.currentTarget.value)}
          autofocus={props.autofocus}
          autocomplete="off"
          autocorrect="off"
          autocapitalize="off"
          spellcheck={false}
        />
        <Show when={props.browse}>
          {(browse) => (
            <button
              type="button"
              class="btn-secondary picker-browse"
              aria-label={browse().label}
              aria-haspopup="listbox"
              aria-expanded={props.open}
              disabled={!!browse().disabledReason}
              title={browse().disabledReason}
              onClick={props.onToggle}
            >
              Browse
            </button>
          )}
        </Show>
        <Show when={props.open}>
          <Popover anchor={fieldEl} matchWidth onClose={props.onClose}>
            <div id={headingId} class="popover-note picker-heading">{props.heading}</div>
            <div role="listbox" aria-labelledby={headingId}>
              {props.children}
            </div>
          </Popover>
        </Show>
      </div>
    </div>
  );
}

/** One row of either list: a primary line with an optional smaller one beneath. */
function DropdownItem(props: { primary: string; secondary?: string | null; onSelect: () => void }) {
  return (
    <PopoverOption onSelect={props.onSelect}>
      <div class="dropdown-item">
        <span class="dropdown-item-primary">{props.primary}</span>
        <Show when={props.secondary}>
          <span class="dropdown-item-secondary">{props.secondary}</span>
        </Show>
      </div>
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

  // `op vault list` is slow and may prompt for sign-in, so it runs only from the
  // vault Browse button, once per account value.
  const vaultLists = new Map<string, Promise<VaultInfo[]>>();
  function vaultsIn(acct: string) {
    let listing = vaultLists.get(acct);
    if (!listing) {
      listing = listVaults(acct || null);
      vaultLists.set(acct, listing);
      listing.catch(() => vaultLists.delete(acct));
    }
    return listing;
  }
  const [listedAccount, setListedAccount] = createSignal<string>();
  const [vaults, { refetch: retryVaults }] = createResource(listedAccount, vaultsIn);
  const accountName = (value: string) => accountLabel(value || null, accounts()) ?? "the default account";

  function openVaults() {
    const acct = account().trim();
    if (acct === listedAccount() && vaults.error) retryVaults();
    else setListedAccount(acct);
    setOpenDropdown("vault");
  }

  onMount(async () => {
    setSaved(loadSavedLogins());
    fetchUpdate();
    // Both are local, sign-in-free lookups; neither gates the other. A failing
    // account list just leaves account Browse disabled — the op CLI status line below
    // already reports the case where `op` is missing entirely.
    const [status, configured] = await Promise.all([
      invoke<OpCliStatus>("check_op_cli").catch(() => ({ found: false, path: null })),
      listAccounts().catch(() => []),
    ]);
    setOpCli(status);
    setAccounts(configured);
  });

  function toggle(which: Dropdown) {
    if (openDropdown() === which) setOpenDropdown(null);
    else if (which === "vault") openVaults();
    else setOpenDropdown(which);
  }

  function selectLogin(login: SavedLogin) {
    setVault(login.vault);
    setAccount(login.account ?? "");
    setOpenDropdown(null);
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

    let created: string | null = null;
    try {
      if (creating()) {
        created = (await createVault(vault(), account() || null)).name;
        setCreating(false);
        setVault(created);
      }
      const info = await invoke<ConnectionInfo>("connect", {
        vault: created ?? vault(),
        account: account() || null,
      });
      setAppState({
        connected: info.connected,
        vault: info.vault,
        account: info.account,
        vaultState: info.vault_state as VaultState,
      });
      setSaved(addLogin(info.vault, info.account));
      navigate(created ? "/ca" : "/dashboard");
    } catch (err) {
      setError(created
        ? `Created vault "${created}" but couldn't connect: ${errorMessage(err)}. Connect to try again.`
        : errorMessage(err));
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
            id="account"
            label="1Password Account (optional)"
            placeholder="e.g. my.1password.com"
            value={account()}
            onInput={(v) => { setAccount(v); setOpenDropdown(null); }}
            autofocus
            browse={{
              label: "Browse 1Password accounts",
              disabledReason: accounts().length > 0 ? undefined : "No accounts are configured in the op CLI",
            }}
            heading="Accounts in the op CLI"
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

          <PickerField
            id="vault"
            label={creating() ? "New 1Password Vault" : "1Password Vault"}
            placeholder="e.g. Private CA"
            value={vault()}
            onInput={(v) => { setVault(v); setOpenDropdown(null); }}
            browse={creating() ? undefined : { label: `Browse vaults in ${accountName(account().trim())}` }}
            heading={`Vaults in ${accountName(listedAccount() ?? "")}`}
            open={openDropdown() === "vault"}
            onToggle={() => toggle("vault")}
            onClose={() => setOpenDropdown(null)}
          >
            <Show when={vaults.state === "ready"}>
              <For each={vaults()}>
                {(v) => <DropdownItem primary={v.name} onSelect={() => { setVault(v.name); setOpenDropdown(null); }} />}
              </For>
            </Show>
            <Show when={vaults.loading}>
              <div class="popover-note"><Spinner message="Loading vaults…" small /></div>
            </Show>
            <Show when={vaults.error}>
              {(err) => <div class="popover-note popover-error">{errorMessage(err())}</div>}
            </Show>
            <Show when={vaults.state === "ready" && vaults().length === 0}>
              <div class="popover-note">No vaults found</div>
            </Show>
          </PickerField>

          {error() && <p class="connect-error" role="alert">{error()}</p>}

          <button class="btn-primary connect-btn" type="submit" disabled={loading() || !vault().trim()}>
            {creating()
              ? loading() ? "Creating…" : "Create vault"
              : loading() ? "Connecting…" : "Connect"}
          </button>
        </form>

        <Show when={!creating() && saved().length > 0}>
          <section class="connect-recent" aria-labelledby="connect-recent-title">
            <h2 id="connect-recent-title" class="connect-recent-title">Recent</h2>
            <ul class="connect-recent-list">
              <For each={saved()}>
                {(login) => {
                  const label = () => accountLabel(login.account, accounts()) ?? "default account";
                  return (
                    <li class="connect-recent-row">
                      <button type="button" class="connect-recent-pick" onClick={() => selectLogin(login)}>
                        <span class="dropdown-item-primary">{login.vault}</span>
                        <span class="dropdown-item-secondary">{label()}</span>
                      </button>
                      <button
                        type="button"
                        class="saved-forget"
                        aria-label={`Forget ${login.vault} in ${label()}`}
                        title="Forget this login"
                        onClick={() => setSaved(removeLogin(login.vault, login.account))}
                      >
                        &times;
                      </button>
                    </li>
                  );
                }}
              </For>
            </ul>
          </section>
        </Show>

        <button class="btn-ghost connect-mode-switch" type="button" onClick={switchMode} disabled={loading()}>
          {creating() ? "Connect to an existing vault" : "New CA in a new vault…"}
        </button>

        <div class="connect-scheme">
          <SchemePicker />
        </div>

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
