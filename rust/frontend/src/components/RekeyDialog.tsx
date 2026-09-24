import { createEffect, createSignal } from "solid-js";
import type { JSX } from "solid-js";
import ConfirmDialog from "./ConfirmDialog";
import KeyAlgorithmSelect from "./KeyAlgorithmSelect";
import type { KeyAlgorithm } from "../api/types";

export default function RekeyDialog(props: {
  open: boolean;
  title: string;
  message: JSX.Element | string;
  onClose: () => void;
  onConfirm: (keyAlgorithm: KeyAlgorithm | null) => Promise<void>;
}) {
  const [keyAlgorithm, setKeyAlgorithm] = createSignal<KeyAlgorithm | null>(null);
  createEffect(() => {
    if (props.open) setKeyAlgorithm(null);
  });

  return (
    <ConfirmDialog
      open={props.open}
      title={props.title}
      message={props.message}
      confirmLabel="Rekey"
      actingLabel="Rekeying…"
      onClose={props.onClose}
      onConfirm={() => props.onConfirm(keyAlgorithm())}
    >
      <KeyAlgorithmSelect value={keyAlgorithm()} onChange={setKeyAlgorithm} keepCurrent />
    </ConfirmDialog>
  );
}
