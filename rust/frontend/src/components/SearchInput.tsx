import { Show } from "solid-js";

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

      <style>{`
        .search-input-wrap {
          position: relative;
          display: flex;
          align-items: center;
        }

        .search-input {
          padding: 6px 28px 6px 10px;
          background: var(--bg-elevated);
          border: 1px solid var(--border);
          border-radius: 6px;
          color: var(--text-primary);
          font-size: 0.8125rem;
          min-width: 160px;
        }

        .search-input::placeholder {
          color: var(--text-tertiary);
        }

        .search-clear {
          position: absolute;
          right: 4px;
          background: none;
          border: none;
          color: var(--text-tertiary);
          cursor: pointer;
          font-size: 1rem;
          padding: 2px 6px;
          line-height: 1;
        }

        .search-clear:hover {
          color: var(--text-primary);
        }
      `}</style>
    </div>
  );
}
