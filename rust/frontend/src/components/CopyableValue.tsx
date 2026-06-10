import { Show } from "solid-js";
import { createCopiedSignal, writeClipboard } from "../utils/clipboard";
import CopyIcon from "./CopyIcon";
import "../styles/components/copyable-value.css";

interface CopyableValueProps {
  value: string | null | undefined;
  mono?: boolean;
}

/**
 * A detail value that copies itself to the clipboard on click. Renders the
 * value text with a copy icon as the affordance and flips to "Copied" for a
 * couple of seconds after a successful copy. Falls back to a plain dash when
 * there's nothing to copy.
 */
export default function CopyableValue(props: CopyableValueProps) {
  const [copied, markCopied] = createCopiedSignal();

  return (
    <Show
      when={props.value}
      fallback={<span class="detail-value">{"—"}</span>}
    >
      <button
        type="button"
        class={`copyable-value ${props.mono ? "mono" : ""}`}
        title="Copy to clipboard"
        onClick={() => {
          void writeClipboard(props.value!);
          markCopied();
        }}
      >
        <span class="copyable-value-text">{props.value}</span>
        <Show when={copied()} fallback={<CopyIcon />}>
          <span class="copyable-value-copied">Copied</span>
        </Show>
      </button>
    </Show>
  );
}
