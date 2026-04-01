import { Show } from "solid-js";
import "../styles/components/search-input.css";

interface SearchInputProps {
  value: string;
  onInput: (value: string) => void;
  placeholder?: string;
}

export default function SearchInput(props: SearchInputProps) {
  return (
    <div class="search-input-wrap">
      <input
        type="text"
        class="search-input"
        placeholder={props.placeholder ?? "Search\u2026"}
        value={props.value}
        onInput={(e) => props.onInput(e.currentTarget.value)}
        autocomplete="off"
        autocorrect="off"
        autocapitalize="off"
        spellcheck={false}
      />
      <Show when={props.value}>
        <button
          class="search-clear"
          onClick={() => props.onInput("")}
          type="button"
          aria-label="Clear search"
        >
          &times;
        </button>
      </Show>
    </div>
  );
}
