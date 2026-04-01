import { Show, onMount, onCleanup } from "solid-js";
import type { JSX } from "solid-js";

interface ModalProps {
  open: boolean;
  onClose: () => void;
  title?: string;
  children: JSX.Element;
}

export default function Modal(props: ModalProps): JSX.Element {
  function onKeyDown(e: KeyboardEvent) {
    if (e.key === "Escape") props.onClose();
  }

  onMount(() => document.addEventListener("keydown", onKeyDown));
  onCleanup(() => document.removeEventListener("keydown", onKeyDown));

  return (
    <Show when={props.open}>
      <div class="modal-overlay" onClick={props.onClose}>
        <div class="modal-dialog" onClick={(e) => e.stopPropagation()}>
          <div class="modal-header">
            <Show when={props.title}>
              <h3 class="modal-title">{props.title}</h3>
            </Show>
            <button class="modal-close btn-ghost" onClick={props.onClose}>
              &times;
            </button>
          </div>
          <div class="modal-body">
            {props.children}
          </div>
        </div>
      </div>
    </Show>
  );
}
