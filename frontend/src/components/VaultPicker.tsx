import { Show, For, createSignal } from "solid-js";
import { listVaults, createVault } from "../api/vaults";
import Spinner from "./Spinner";
import { appState } from "../stores/app";
import Popover, { PopoverOption } from "./Popover";
import type { VaultInfo } from "../api/types";
import "../styles/components/vault-picker.css";

interface VaultPickerProps {
  /** Current vault name value. */
  value: string;
  /** Called when the user selects or types a vault name. */
  onChange: (vault: string) => void;
  /** Placeholder text for the input. */
  placeholder?: string;
}

/**
 * Text input with a "Browse" button that opens a dropdown of 1Password vaults.
 * Includes a "New vault" option to create and auto-select a new vault.
 *
 * Usage:
 *   <VaultPicker value={vault()} onChange={setVault} />
 */
export default function VaultPicker(props: VaultPickerProps) {
  const [open, setOpen] = createSignal(false);
  let rowEl!: HTMLDivElement;
  const [vaultList, setVaultList] = createSignal<VaultInfo[]>([]);
  const [loading, setLoading] = createSignal(false);
  const [fetchError, setFetchError] = createSignal<string | null>(null);

  // New vault creation
  const [showCreate, setShowCreate] = createSignal(false);
  const [newVaultName, setNewVaultName] = createSignal("");
  const [creating, setCreating] = createSignal(false);
  const [createError, setCreateError] = createSignal<string | null>(null);

  function selectVault(name: string) {
    props.onChange(name);
    setOpen(false);
    setShowCreate(false);
  }

  async function fetchVaults() {
    setLoading(true);
    setFetchError(null);
    try {
      const result = await listVaults();
      setVaultList(result);
    } catch (e) {
      setFetchError(String(e));
    } finally {
      setLoading(false);
    }
  }

  function toggleBrowse() {
    const next = !open();
    setOpen(next);
    if (next) {
      setShowCreate(false);
      setCreateError(null);
      fetchVaults();
    }
  }

  async function handleCreateVault() {
    const name = newVaultName().trim();
    if (!name) return;
    setCreating(true);
    setCreateError(null);
    try {
      const vault = await createVault(name, appState.account);
      setNewVaultName("");
      setShowCreate(false);
      selectVault(vault.name);
    } catch (e) {
      setCreateError(String(e));
    } finally {
      setCreating(false);
    }
  }

  return (
    <>
      <div ref={rowEl} class="vault-picker-row">
        <input
          type="text"
          placeholder={props.placeholder ?? "e.g. client-vault"}
          value={props.value}
          onInput={(e) => props.onChange(e.currentTarget.value)}
          autocomplete="off"
          autocorrect="off"
          autocapitalize="off"
          spellcheck={false}
        />
        <button
          type="button"
          class="btn-ghost"
          aria-haspopup="listbox"
          aria-expanded={open()}
          onClick={toggleBrowse}
        >
          Browse
        </button>
      </div>

      <Show when={open()}>
        <Popover anchor={rowEl} matchWidth onClose={() => setOpen(false)} class="vault-picker-menu">
          <Show when={showCreate()}>
            <div class="vault-picker-create-form">
              <input
                autofocus
                type="text"
                placeholder="Vault name"
                value={newVaultName()}
                onInput={(e) => setNewVaultName(e.currentTarget.value)}
                onKeyDown={(e) => { if (e.key === "Enter") handleCreateVault(); }}
                autocomplete="off"
                autocorrect="off"
                autocapitalize="off"
                spellcheck={false}
              />
              <button
                class="btn-primary btn-sm"
                onClick={handleCreateVault}
                disabled={creating() || !newVaultName().trim()}
              >
                {creating() ? "Creating..." : "Create"}
              </button>
              <button
                class="btn-ghost btn-sm"
                onClick={() => { setShowCreate(false); setCreateError(null); }}
              >
                Cancel
              </button>
            </div>
            <Show when={createError()}>
              <div class="popover-note popover-error">{createError()}</div>
            </Show>
          </Show>

          <div role="listbox" aria-label="Vaults">
            <Show when={!showCreate()}>
              <PopoverOption
                class="vault-picker-new"
                onSelect={() => { setShowCreate(true); setNewVaultName(""); setCreateError(null); }}
              >
                + New vault
              </PopoverOption>
            </Show>
            <Show when={!loading()}>
              <For each={vaultList()}>
                {(v) => (
                  <PopoverOption selected={v.name === props.value} onSelect={() => selectVault(v.name)}>
                    {v.name}
                  </PopoverOption>
                )}
              </For>
            </Show>
          </div>

          <Show when={loading()}>
            <div class="popover-note">
              <Spinner message="Loading vaults..." small />
            </div>
          </Show>

          <Show when={fetchError()}>
            <div class="popover-note popover-error">{fetchError()}</div>
          </Show>

          <Show when={!loading() && !fetchError() && vaultList().length === 0}>
            <div class="popover-note">No vaults found</div>
          </Show>
        </Popover>
      </Show>
    </>
  );
}
