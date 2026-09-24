import { For, Show, createSignal } from "solid-js";
import Popover from "./Popover";
import "../styles/components/kebab-menu.css";

export interface KebabItem {
  label: string;
  onSelect: () => void;
  disabled?: boolean;
  danger?: boolean;
}

interface KebabMenuProps {
  items: KebabItem[];
  /** Accessible label for the trigger button. */
  ariaLabel?: string;
}

/** A "⋮" trigger that opens a small popover of actions. */
export default function KebabMenu(props: KebabMenuProps) {
  const [open, setOpen] = createSignal(false);
  let triggerEl!: HTMLButtonElement;

  return (
    <>
      <button
        ref={triggerEl}
        type="button"
        class="kebab-btn"
        aria-label={props.ariaLabel ?? "Actions"}
        aria-haspopup="menu"
        aria-expanded={open()}
        onClick={(e) => {
          e.stopPropagation();
          setOpen(!open());
        }}
      >
        <span aria-hidden="true">⋮</span>
      </button>
      <Show when={open()}>
        <Popover
          anchor={triggerEl}
          align="end"
          role="menu"
          class="kebab-menu"
          focusFirstItem
          onClose={() => setOpen(false)}
        >
          <For each={props.items}>
            {(item) => (
              <button
                type="button"
                role="menuitem"
                class="kebab-item"
                classList={{ "kebab-item-danger": item.danger }}
                disabled={item.disabled}
                onClick={() => {
                  setOpen(false);
                  item.onSelect();
                }}
              >
                {item.label}
              </button>
            )}
          </For>
        </Popover>
      </Show>
    </>
  );
}
