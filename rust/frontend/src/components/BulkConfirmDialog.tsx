import { Show, createSignal, createEffect } from "solid-js";
import type { JSX } from "solid-js";
import Modal from "./Modal";

interface BulkConfirmDialogProps {
  open: boolean;
  title: string;
  message: JSX.Element | string;
  confirmLabel: string;
  /** Label shown on the confirm button while the action runs. */
  actingLabel: string;
  danger?: boolean;
  /** When set, render a required reason input and pass it to `onConfirm`. */
  requireReason?: boolean;
  reasonPlaceholder?: string;
  onClose: () => void;
  /** Runs the action; the dialog owns the acting/error state and closes on
   * success. Receives the trimmed reason (empty string when not required). */
  onConfirm: (reason: string) => Promise<void>;
}

/**
 * Generic confirmation dialog for bulk (and one-off destructive) actions.
 * Owns acting + error state and, optionally, a required reason field — so the
 * various bulk call sites stay a single element. Mirrors the single-cert
 * Revoke/Ignore dialogs.
 */
export default function BulkConfirmDialog(props: BulkConfirmDialogProps) {
  const [reason, setReason] = createSignal("");
  const [acting, setActing] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  createEffect(() => {
    if (props.open) {
      setReason("");
      setError(null);
    }
  });

  const reasonOk = () => !props.requireReason || !!reason().trim();

  async function handleConfirm() {
    if (!reasonOk()) return;
    setActing(true);
    setError(null);
    try {
      await props.onConfirm(reason().trim());
      props.onClose();
    } catch (e) {
      setError(String(e));
    } finally {
      setActing(false);
    }
  }

  return (
    <Modal open={props.open} onClose={props.onClose} title={props.title}>
      <p class="confirm-message">{props.message}</p>
      <Show when={props.requireReason}>
        <div class="form-group">
          <label class="form-label">Reason</label>
          <input
            type="text"
            class="form-input"
            value={reason()}
            onInput={(e) => setReason(e.currentTarget.value)}
            placeholder={props.reasonPlaceholder ?? "Reason for the audit trail"}
            disabled={acting()}
            autofocus
          />
        </div>
      </Show>
      <Show when={error()}>
        <p class="page-error" role="alert">{error()}</p>
      </Show>
      <div class="form-actions">
        <button
          class={props.danger ? "btn-danger" : "btn-primary"}
          onClick={handleConfirm}
          disabled={acting() || !reasonOk()}
        >
          {acting() ? props.actingLabel : props.confirmLabel}
        </button>
        <button class="btn-ghost" onClick={props.onClose} disabled={acting()}>
          Cancel
        </button>
      </div>
    </Modal>
  );
}
