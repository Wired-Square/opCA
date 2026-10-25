import { Show, createSignal } from "solid-js";
import type { JSX } from "solid-js";
import { Confirm } from "@wired-square/kit";
import KeyAlgorithmSelect from "./KeyAlgorithmSelect";
import type { KeyAlgorithm } from "../api/types";
import { createActing } from "../utils/acting";

interface RekeyDialogProps {
  open: boolean;
  title: string;
  message: JSX.Element | string;
  onClose: () => void;
  onConfirm: (keyAlgorithm: KeyAlgorithm | null) => Promise<void>;
}

export default function RekeyDialog(props: RekeyDialogProps) {
  return (
    <Show when={props.open}>
      <RekeyConfirm {...props} />
    </Show>
  );
}

function RekeyConfirm(props: Omit<RekeyDialogProps, "open">) {
  const [keyAlgorithm, setKeyAlgorithm] = createSignal<KeyAlgorithm | null>(null);
  const acting = createActing();

  return (
    <Confirm
      title={props.title}
      verb={acting.verb("Rekey", "Rekeying…")}
      tone="primary"
      onClose={props.onClose}
      act={acting.act(() => props.onConfirm(keyAlgorithm()))}
    >
      <p class="confirm-message">{props.message}</p>
      <KeyAlgorithmSelect value={keyAlgorithm()} onChange={setKeyAlgorithm} keepCurrent />
    </Confirm>
  );
}
