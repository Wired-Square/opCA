import { Show, For, createSignal } from "solid-js";
import { listVaults, createVault } from "../api/vaults";
import Spinner from "./Spinner";
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
      const vault = await createVault(name);
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
    <div class="vault-picker" onClick={(e) => e.stopPropagation()}>
      <div class="vault-picker-row">
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
          onClick={toggleBrowse}
        >
          Browse
        </button>
      </div>

      <Show when={open()}>
        <div class="vault-picker-dropdown">
          {/* New vault — at the top */}
          <div class="vault-picker-create-section">
            <Show when={!showCreate()}>
              <div
                class="vault-picker-item vault-picker-new"
                onClick={() => { setShowCreate(true); setNewVaultName(""); setCreateError(null); }}
              >
                + New vault
              </div>
            </Show>

            <Show when={showCreate()}>
              <div class="vault-picker-create-form">
                <input
                  ref={(el) => setTimeout(() => el.focus(), 0)}
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
                <div class="vault-picker-error">{createError()}</div>
              </Show>
            </Show>
          </div>

          <Show when={loading()}>
            <div class="vault-picker-loading">
              <Spinner message="Loading vaults..." small />
            </div>
          </Show>

          <Show when={fetchError()}>
            <div class="vault-picker-error">{fetchError()}</div>
          </Show>

          <Show when={!loading() && vaultList().length > 0}>
            <For each={vaultList()}>
              {(v) => (
                <div
                  class={`vault-picker-item ${v.name === props.value ? "vault-picker-item-selected" : ""}`}
                  onClick={() => selectVault(v.name)}
                >
                  {v.name}
                </div>
              )}
            </For>
          </Show>

          <Show when={!loading() && !fetchError() && vaultList().length === 0}>
            <div class="vault-picker-empty">No vaults found</div>
          </Show>
        </div>
      </Show>
    </div>
  );
}
