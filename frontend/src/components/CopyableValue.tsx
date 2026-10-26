import { Show } from "solid-js";
import { CopyButton } from "@wired-square/kit";
import { writeClipboard } from "../utils/clipboard";
import "../styles/components/copyable-value.css";

interface CopyableValueProps {
  value: string | null | undefined;
  mono?: boolean;
}

/** A detail value that copies itself on click, or a dash when there is none. */
export default function CopyableValue(props: CopyableValueProps) {
  return (
    <Show when={props.value} fallback={<span class="detail-value">{"—"}</span>}>
      {(value) => (
        <span class="copyable-value" classList={{ mono: props.mono }} title="Copy to clipboard">
          <CopyButton value={value()} write={writeClipboard}>
            {value()}
          </CopyButton>
        </span>
      )}
    </Show>
  );
}
