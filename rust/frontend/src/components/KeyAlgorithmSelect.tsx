import { For } from "solid-js";
import { KEY_ALGORITHMS, type KeyAlgorithm } from "../api/types";

export default function KeyAlgorithmSelect(props: {
  value: KeyAlgorithm;
  onChange: (value: KeyAlgorithm) => void;
}) {
  return (
    <div class="form-group">
      <label class="form-label" for="key-algorithm">Key Type</label>
      <select
        id="key-algorithm"
        value={props.value}
        onChange={(e) => props.onChange(e.currentTarget.value as KeyAlgorithm)}
      >
        <For each={KEY_ALGORITHMS}>{(k) => <option value={k.value}>{k.label}</option>}</For>
      </select>
    </div>
  );
}
