import { For, Show } from "solid-js";
import { KEY_ALGORITHMS, type KeyAlgorithm } from "../api/types";

export default function KeyAlgorithmSelect<T extends KeyAlgorithm | null>(props: {
  value: T;
  onChange: (value: T) => void;
  keepCurrent?: boolean;
}) {
  return (
    <div class="form-group">
      <label class="form-label" for="key-algorithm">Key Type</label>
      <select
        id="key-algorithm"
        value={props.value ?? ""}
        onChange={(e) => props.onChange((e.currentTarget.value || null) as T)}
      >
        <Show when={props.keepCurrent}>
          <option value="">Keep current</option>
        </Show>
        <For each={KEY_ALGORITHMS}>{(k) => <option value={k.value}>{k.label}</option>}</For>
      </select>
    </div>
  );
}
