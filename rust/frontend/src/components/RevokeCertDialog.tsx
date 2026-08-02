import { Show, createSignal } from "solid-js";
import { revokeCert } from "../api/certs";
import Modal from "./Modal";
import { certLabel } from "../api/certActions";

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
  const [acting, setActing] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  async function handleConfirm() {
    const serial = props.serial;
    if (!serial) return;
    setActing(true);
    setError(null);
    try {
      await revokeCert(serial);
      props.onDone();
      props.onClose();
    } catch (e) {
      setError(String(e));
    } finally {
      setActing(false);
    }
  }

  return (
    <Modal open={props.open} onClose={props.onClose} title="Revoke Certificate">
      <p class="confirm-message">
        Revoke <span class="mono">{certLabel(props)}</span>? This cannot
        be undone.
      </p>
      <Show when={error()}>
        <p class="page-error" role="alert">{error()}</p>
      </Show>
      <div class="form-actions">
        <button class="btn-danger" onClick={handleConfirm} disabled={acting()}>
          {acting() ? "Revoking…" : "Revoke"}
        </button>
        <button class="btn-ghost" onClick={props.onClose} disabled={acting()}>
          Cancel
        </button>
      </div>
    </Modal>
  );
}
