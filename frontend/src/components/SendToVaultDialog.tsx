import { Show } from "solid-js";
import type { ProfileRef } from "../api/types";
import Modal from "./Modal";
import SendToVault from "./SendToVault";

interface SendToVaultDialogProps {
  open: boolean;
  /** One profile (kebab) or many (bulk select); all go to the same vault. */
  profiles: ProfileRef[];
  onClose: () => void;
  /** Called once every profile sent successfully, with the vault and the sent profiles. */
  onDone: (vault: string, sent: ProfileRef[]) => void;
}

/** Send one or many generated VPN profiles to another 1Password vault. */
export default function SendToVaultDialog(props: SendToVaultDialogProps) {
  const multi = () => props.profiles.length > 1;
  return (
    <Modal
      open={props.open}
      onClose={props.onClose}
      title={multi() ? "Send Profiles to Vault" : "Send Profile to Vault"}
    >
      <p class="confirm-message">
        Copy{" "}
        <Show when={multi()} fallback={<span class="mono">{props.profiles[0]?.title ?? props.profiles[0]?.cn}</span>}>
          {props.profiles.length} profiles
        </Show>{" "}
        to another 1Password vault.
      </p>
      <SendToVault
        profiles={props.profiles}
        label="Destination vault"
        onDone={(vault, { sent, failed }) => {
          // Keep the dialog open on partial failure so the per-profile list shows.
          if (failed.length === 0) {
            props.onDone(vault, sent);
            props.onClose();
          }
        }}
      >
        <button class="btn-ghost" onClick={props.onClose}>Cancel</button>
      </SendToVault>
    </Modal>
  );
}
