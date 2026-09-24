import { createSignal, createUniqueId, For, Show } from "solid-js";
import { classifySan, SAN_KIND_LABEL, SAN_KIND_TAG } from "../utils/san";

const IDLE_HINT = "Hostname, IP address, email or URI, e.g. www.example.com, 10.0.0.5, ops@example.com, spiffe://prod/web";

/** Chip input for Subject Alternative Names that validates as you type. */
export default function SanInput(props: { values: string[]; onChange: (values: string[]) => void }) {
  const id = createUniqueId();
  const [draft, setDraft] = createSignal("");

  const check = () => {
    const v = draft().trim();
    if (!v) return null;
    if (props.values.includes(v)) return { error: "Already added" };
    return classifySan(v);
  };
  const kind = () => {
    const c = check();
    return c && "kind" in c ? c.kind : null;
  };
  const error = () => {
    const c = check();
    return c && "error" in c ? c.error : null;
  };

  function add() {
    if (!kind()) return;
    props.onChange([...props.values, draft().trim()]);
    setDraft("");
  }

  return (
    <div class="form-group">
      <label class="form-label" for={`${id}-input`}>Subject Alternative Names</label>
      <div class="san-input-row">
        <input
          id={`${id}-input`}
          type="text"
          placeholder="hostname, IP, email or URI"
          value={draft()}
          onInput={(e) => setDraft(e.currentTarget.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") { e.preventDefault(); add(); }
          }}
          aria-invalid={error() ? "true" : undefined}
          aria-describedby={`${id}-hint`}
          autocomplete="off"
          autocorrect="off"
          autocapitalize="off"
          spellcheck={false}
        />
        <button type="button" class="btn-ghost" onClick={add} disabled={!kind()}>Add</button>
      </div>
      <p
        id={`${id}-hint`}
        class="form-hint"
        classList={{ "is-valid": !!kind(), "is-invalid": !!error() }}
        aria-live="polite"
      >
        {kind() ? `✓ ${SAN_KIND_LABEL[kind()!]}` : error() ? `✗ ${error()}` : IDLE_HINT}
      </p>
      <Show when={props.values.length > 0}>
        <div class="san-list">
          <For each={props.values}>
            {(value, i) => {
              const check = classifySan(value);
              return (
                <span class="san-tag">
                  {"kind" in check && <span class="san-kind">{SAN_KIND_TAG[check.kind]}</span>}
                  {value}
                  <button
                    type="button"
                    class="san-remove"
                    aria-label={`Remove ${value}`}
                    onClick={() => props.onChange(props.values.filter((_, j) => j !== i()))}
                  >
                    &times;
                  </button>
                </span>
              );
            }}
          </For>
        </div>
      </Show>
    </div>
  );
}
