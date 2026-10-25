import { Show, createSignal } from "solid-js";
import { Confirm } from "@wired-square/kit";
import { resignCa } from "../api/ca";
import { createActing } from "../utils/acting";

interface ResignCaDialogProps {
  open: boolean;
  onClose: () => void;
  /** Called with the accepted validity after a successful re-sign, so the
   * caller can report the outcome and refresh. */
  onDone: (days: number) => void;
}

/**
 * Confirmation for re-signing the CA certificate. Re-sign keeps the key,
 * subject and serial — so issued certificates still chain — but it overwrites
 * the certificate in 1Password with no snapshot taken, which opCA cannot undo.
 * That is why it is gated like the other destructive actions rather than by an
 * expanding panel.
 */
export default function ResignCaDialog(props: ResignCaDialogProps) {
  return (
    <Show when={props.open}>
      <ResignCaConfirm {...props} />
    </Show>
  );
}

function ResignCaConfirm(props: Omit<ResignCaDialogProps, "open">) {
  const [days, setDays] = createSignal("3650");
  const acting = createActing();

  const parsedDays = () => {
    const n = parseInt(days(), 10);
    return n > 0 ? n : null;
  };

  return (
    <Confirm
      title="Re-sign CA Certificate"
      verb={acting.verb("Re-sign CA", "Re-signing…")}
      disabled={parsedDays() === null}
      onClose={props.onClose}
      act={acting.act(async () => {
        const validity = parsedDays();
        if (validity === null) return;
        await resignCa(validity);
        props.onDone(validity);
      })}
    >
      <p class="confirm-message">
        Re-signs with the same key, subject and serial, so certificates
        already issued by this CA still chain to it. The existing CA
        certificate is replaced in 1Password and{" "}
        <strong>cannot be recovered</strong>.
      </p>
      <div class="form-group">
        <label class="form-label" for="resign-days">New validity (days)</label>
        <input
          id="resign-days"
          type="number"
          min="1"
          class="max-w-input"
          value={days()}
          onInput={(e) => setDays(e.currentTarget.value)}
        />
      </div>
    </Confirm>
  );
}
