import { Show, createSignal, createEffect } from "solid-js";
import { sendProfileToVault } from "../api/openvpn";
import type { OpenVpnProfileItem } from "../api/types";
import Modal from "./Modal";
import VaultPicker from "./VaultPicker";

interface SendToVaultDialogProps {
  open: boolean;
  profile: OpenVpnProfileItem | null;
  onClose: () => void;
  /** Called after a successful send with the destination vault name. */
  onDone: (vault: string) => void;
}

// Remembered across the session so the dialog pre-fills the last vault a profile
// was successfully sent to. Cleared via the Remove button.
let lastSentVault = "";

/** Send a generated VPN profile to another 1Password vault. */
export default function SendToVaultDialog(props: SendToVaultDialogProps) {
  const [vault, setVault] = createSignal("");
  const [acting, setActing] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  // Pre-fill with the remembered vault each time the dialog opens.
  createEffect(() => {
    if (props.open) {
      setVault(lastSentVault);
      setError(null);
    }
  });

  function removeVault() {
    setVault("");
    lastSentVault = "";
  }

  async function handleSend() {
    const profile = props.profile;
    const dest = vault().trim();
    if (!profile || !dest) return;
    setActing(true);
    setError(null);
    try {
      await sendProfileToVault(profile.title, profile.cn, dest);
      lastSentVault = dest;
      props.onDone(dest);
      props.onClose();
    } catch (e) {
      setError(String(e));
    } finally {
      setActing(false);
    }
  }

  return (
    <Modal open={props.open} onClose={props.onClose} title="Send Profile to Vault">
      <p class="confirm-message">
        Copy <span class="mono">{props.profile?.title ?? props.profile?.cn}</span>{" "}
        to another 1Password vault.
      </p>
      <div class="form-group">
        <div class="form-label-row">
          <label class="form-label">Destination vault</label>
          <Show when={vault().trim()}>
            <button type="button" class="btn-ghost btn-sm" onClick={removeVault}>Remove</button>
          </Show>
        </div>
        <VaultPicker value={vault()} onChange={setVault} />
      </div>
      <Show when={error()}>
        <p class="page-error" role="alert">{error()}</p>
      </Show>
      <div class="form-actions">
        <button class="btn-primary" onClick={handleSend} disabled={acting() || !vault().trim()}>
          {acting() ? "Sending…" : "Send to Vault"}
        </button>
        <button class="btn-ghost" onClick={props.onClose} disabled={acting()}>
          Cancel
        </button>
      </div>
    </Modal>
  );
}
