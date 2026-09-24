import { Show, For, createSignal, onMount, type JSX } from "solid-js";
import { sendProfileToVault } from "../api/openvpn";
import type { ProfileRef } from "../api/types";
import VaultPicker from "./VaultPicker";

interface SendFailure {
  cn: string;
  error: string;
}

interface SendToVaultProps {
  /** One profile = single send; several = bulk send to the same vault. */
  profiles: ProfileRef[];
  label?: string;
  /**
   * Called after a send attempt completes (even with partial failures).
   * `sent` is the snapshot of profiles that succeeded — captured during the
   * loop, so callers never re-read mutable parent state that may have changed
   * (e.g. the dialog being closed) while the send was in flight.
   */
  onDone?: (vault: string, summary: { sent: ProfileRef[]; failed: SendFailure[] }) => void;
  /** Rendered in the action row beside the Send button (e.g. a Done/Cancel button). */
  children?: JSX.Element;
}

// Remembered across the session so every send-to-vault entry point (kebab,
// single generate, bulk generate) pre-fills the last vault used. Cleared via
// the Remove button.
let lastSentVault = "";

/**
 * Inline send-to-vault block: a destination VaultPicker plus a Send button that
 * copies one or many generated profiles to another 1Password vault. Sends are
 * sequential (the vault lock serialises them anyway) and per-profile failures
 * are surfaced without aborting the rest.
 */
export default function SendToVault(props: SendToVaultProps) {
  const [vault, setVault] = createSignal("");
  const [sending, setSending] = createSignal(false);
  const [failures, setFailures] = createSignal<SendFailure[]>([]);

  onMount(() => setVault(lastSentVault));

  function removeVault() {
    setVault("");
    lastSentVault = "";
  }

  async function handleSend() {
    const dest = vault().trim();
    // Snapshot the targets: the parent's `profiles` may change mid-send (e.g. the
    // dialog being closed nulls it), but the loop and result must use this list.
    const targets = props.profiles;
    if (!dest || targets.length === 0) return;
    setSending(true);
    setFailures([]);
    const sent: ProfileRef[] = [];
    const failed: SendFailure[] = [];
    for (const p of targets) {
      try {
        await sendProfileToVault(p.title, p.cn, dest);
        sent.push(p);
      } catch (e) {
        failed.push({ cn: p.cn, error: String(e) });
      }
    }
    setSending(false);
    setFailures(failed);
    lastSentVault = dest;
    props.onDone?.(dest, { sent, failed });
  }

  return (
    <div class="form-group">
      <div class="form-label-row">
        <label class="form-label">{props.label ?? "Send to vault"}</label>
        <Show when={vault().trim()}>
          <button type="button" class="btn-ghost btn-sm" onClick={removeVault}>Remove</button>
        </Show>
      </div>
      <VaultPicker value={vault()} onChange={setVault} />
      <Show when={failures().length > 0}>
        <ul class="failure-list">
          <For each={failures()}>
            {(f) => <li><span class="mono">{f.cn}</span> — {f.error}</li>}
          </For>
        </ul>
      </Show>
      <div class="form-actions">
        <button class="btn-primary" onClick={handleSend} disabled={sending() || !vault().trim()}>
          {sending() ? "Sending…" : "Send to Vault"}
        </button>
        {props.children}
      </div>
    </div>
  );
}
