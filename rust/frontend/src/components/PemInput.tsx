import { tauriInvoke } from "../api/tauri";
import "../styles/components/pem-input.css";

interface PemInputProps {
  label: string;
  placeholder?: string;
  value: string;
  onInput: (value: string) => void;
  rows?: number;
}

/**
 * Reusable PEM input — textarea for pasting PEM content, with a Browse button
 * that opens a native file picker and reads the selected file via Tauri.
 */
export default function PemInput(props: PemInputProps) {
  async function handleBrowse() {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const path = await open({
      multiple: false,
      filters: [{ name: "PEM", extensions: ["pem", "crt", "cer", "key"] }],
    });
    if (!path) return;

    const content = await tauriInvoke<string>("read_text_file", {
      path: path as string,
    });
    props.onInput(content);
  }

  function handleClear() {
    props.onInput("");
  }

  return (
    <div class="form-group">
      <label class="form-label">{props.label}</label>
      <div class="pem-input-row">
        <textarea
          class="pem-textarea"
          placeholder={props.placeholder ?? "Paste PEM content or use Browse\u2026"}
          value={props.value}
          onInput={(e) => props.onInput(e.currentTarget.value)}
          rows={props.rows ?? 6}
          autocomplete="off"
          autocorrect="off"
          autocapitalize="off"
          spellcheck={false}
        />
        <div class="pem-btn-col">
          <button type="button" class="btn-ghost pem-action-btn" onClick={handleBrowse}>
            Browse
          </button>
          <button
            type="button"
            class="btn-ghost pem-action-btn"
            onClick={handleClear}
            disabled={!props.value}
          >
            Clear
          </button>
        </div>
      </div>
    </div>
  );
}
