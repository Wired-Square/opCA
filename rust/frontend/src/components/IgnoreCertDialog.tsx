import { Show, createSignal, createEffect } from "solid-js";
import { ignoreCert } from "../api/certs";
import Modal from "./Modal";
import { certLabel } from "../api/certActions";

interface IgnoreCertDialogProps {
  open: boolean;
  serial: string | null;
  cn: string | null;
  onClose: () => void;
  /** Called after a successful ignore so the caller can refresh. */
  onDone: () => void;
}

/**
 * Unified "ignore certificate" dialog used from both the certificates list and
 * the certificate detail page. A reason is required — Confirm stays disabled
 * until the field is non-empty.
 */
export default function IgnoreCertDialog(props: IgnoreCertDialogProps) {
  const [reason, setReason] = createSignal("");
  const [acting, setActing] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  // Reset the form whenever the dialog (re)opens.
  createEffect(() => {
    if (props.open) {
      setReason("");
      setError(null);
    }
  });

  async function handleConfirm() {
    const serial = props.serial;
    const trimmed = reason().trim();
    if (!serial || !trimmed) return;
    setActing(true);
    setError(null);
    try {
      await ignoreCert(serial, trimmed);
      props.onDone();
      props.onClose();
    } catch (e) {
      setError(String(e));
    } finally {
      setActing(false);
    }
  }

  return (
    <Modal open={props.open} onClose={props.onClose} title="Ignore Certificate">
      <p class="confirm-message">
        Stop counting{" "}
        <span class="mono">{certLabel(props)}</span>{" "}
        toward expiry alerts. Provide a reason for the audit trail.
      </p>
      <div class="form-group">
        <label class="form-label">Reason</label>
        <input
          type="text"
          class="form-input"
          value={reason()}
          onInput={(e) => setReason(e.currentTarget.value)}
          placeholder="Why is this being ignored?"
          disabled={acting()}
          autofocus
        />
      </div>
      <Show when={error()}>
        <p class="page-error" role="alert">{error()}</p>
      </Show>
      <div class="form-actions">
        <button
          class="btn-primary"
          onClick={handleConfirm}
          disabled={acting() || !reason().trim()}
        >
          {acting() ? "Ignoring…" : "Confirm Ignore"}
        </button>
        <button class="btn-ghost" onClick={props.onClose} disabled={acting()}>
          Cancel
        </button>
      </div>
    </Modal>
  );
}
