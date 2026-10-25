import { Show } from "solid-js";
import { Confirm } from "@wired-square/kit";
import { revokeCert } from "../api/certs";
import { certLabel } from "../api/certActions";
import { createActing } from "../utils/acting";

interface RevokeCertDialogProps {
  open: boolean;
  serial: string | null;
  cn: string | null;
  onClose: () => void;
  /** Called after a successful revoke so the caller can refresh. */
  onDone: () => void;
}

/**
 * Unified revoke-confirmation dialog used from both the certificates list and
 * the certificate detail page. Owns the revoke call so both call sites are a
 * single element.
 */
export default function RevokeCertDialog(props: RevokeCertDialogProps) {
  const acting = createActing();
  return (
    <Show when={props.open}>
      <Confirm
        title="Revoke Certificate"
        verb={acting.verb("Revoke", "Revoking…")}
        disabled={!props.serial}
        onClose={props.onClose}
        act={acting.act(async () => {
          const serial = props.serial;
          if (!serial) return;
          await revokeCert(serial);
          props.onDone();
        })}
      >
        Revoke <span class="mono">{certLabel(props)}</span>? This cannot be
        undone.
      </Confirm>
    </Show>
  );
}
