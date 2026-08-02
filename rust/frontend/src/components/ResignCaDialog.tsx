import { createEffect, createSignal } from "solid-js";
import { resignCa } from "../api/ca";
import ConfirmDialog from "./ConfirmDialog";

interface ResignCaDialogProps {
  open: boolean;
  onClose: () => void;
  /** Called with the accepted validity after a successful re-sign, so the
   * caller can report the outcome and refresh. */
  onDone: (days: number) => void;
}

const DEFAULT_DAYS = "3650";

/**
 * Confirmation for re-signing the CA certificate. Re-sign keeps the key,
 * subject and serial — so issued certificates still chain — but it overwrites
 * the certificate in 1Password with no snapshot taken, which opCA cannot undo.
 * That is why it is gated like the other destructive actions rather than by an
 * expanding panel.
 */
export default function ResignCaDialog(props: ResignCaDialogProps) {
  const [days, setDays] = createSignal(DEFAULT_DAYS);

  // The dialog stays mounted, so a typed-then-cancelled value would otherwise
  // survive into the next open.
  createEffect(() => {
    if (props.open) setDays(DEFAULT_DAYS);
  });

  const parsedDays = () => {
    const n = parseInt(days(), 10);
    return n > 0 ? n : null;
  };

  return (
    <ConfirmDialog
      open={props.open}
      title="Re-sign CA Certificate"
      message={
        <>
          Re-signs with the same key, subject and serial, so certificates
          already issued by this CA still chain to it. The existing CA
          certificate is replaced in 1Password and{" "}
          <strong>cannot be recovered</strong>.
        </>
      }
      confirmLabel="Re-sign CA"
      actingLabel="Re-signing…"
      danger
      canConfirm={() => parsedDays() !== null}
      onClose={props.onClose}
      onConfirm={async () => {
        const validity = parsedDays();
        if (validity === null) return;
        await resignCa(validity);
        props.onDone(validity);
      }}
    >
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
    </ConfirmDialog>
  );
}
