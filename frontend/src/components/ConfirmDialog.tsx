import { Show, createSignal, createEffect } from "solid-js";
import { errorMessage } from "../api/tauri";
import type { JSX } from "solid-js";
import Modal from "./Modal";
import PageError from "./PageError";

interface ConfirmDialogProps {
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
  /** Extra fields, rendered below the message. Callers owning their own input
   * gate the confirm button with `canConfirm`. */
  children?: JSX.Element;
  canConfirm?: () => boolean;
  onClose: () => void;
  /** Runs the action; the dialog owns the acting/error state and closes on
   * success. Receives the trimmed reason (empty string when not required). */
  onConfirm: (reason: string) => Promise<void>;
}

/**
 * Confirmation dialog for destructive actions, bulk or one-off. Owns acting +
 * error state and, optionally, a required reason field — so call sites stay a
 * single element.
 */
export default function ConfirmDialog(props: ConfirmDialogProps) {
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
  const canConfirm = () => reasonOk() && (props.canConfirm?.() ?? true);

  async function handleConfirm() {
    if (!canConfirm()) return;
    setActing(true);
    setError(null);
    try {
      await props.onConfirm(reason().trim());
      props.onClose();
    } catch (e) {
      setError(errorMessage(e));
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
      {props.children}
      <PageError message={error()} />
      <div class="form-actions">
        <button
          class={props.danger ? "btn-danger" : "btn-primary"}
          onClick={handleConfirm}
          disabled={acting() || !canConfirm()}
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
