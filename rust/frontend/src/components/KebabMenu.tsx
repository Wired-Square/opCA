import { For, Show, createSignal, onCleanup } from "solid-js";
import { Portal } from "solid-js/web";
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

/**
 * A "⋮" trigger that opens a small popover of actions. The popover is rendered
 * through a Portal and positioned `fixed` off the trigger's bounding box so it
 * is never clipped by a scrolling/overflow ancestor (e.g. the certs table's
 * `.data-table-wrap`). Closes on outside-click, Escape, scroll, or resize.
 */
export default function KebabMenu(props: KebabMenuProps) {
  const [open, setOpen] = createSignal(false);
  const [pos, setPos] = createSignal({ top: 0, left: 0 });
  let triggerEl: HTMLButtonElement | undefined;
  let menuEl: HTMLDivElement | undefined;

  function onDocMouseDown(e: MouseEvent) {
    const t = e.target as Node;
    if (triggerEl?.contains(t) || menuEl?.contains(t)) return;
    close();
  }

  function onKeyDown(e: KeyboardEvent) {
    if (e.key === "Escape") close();
  }

  function close() {
    setOpen(false);
    document.removeEventListener("mousedown", onDocMouseDown);
    document.removeEventListener("keydown", onKeyDown);
    // A scroll or resize invalidates the anchored position; dismissing is
    // simpler (and less jarring) than chasing the trigger.
    window.removeEventListener("scroll", close, true);
    window.removeEventListener("resize", close);
  }

  onCleanup(close);

  function toggle(e: MouseEvent) {
    e.stopPropagation();
    if (open()) {
      close();
      return;
    }
    const r = triggerEl!.getBoundingClientRect();
    // Anchor the menu's top-right corner under the trigger; the CSS shifts it
    // left by its own width via translateX(-100%).
    setPos({ top: r.bottom + 4, left: r.right });
    setOpen(true);
    document.addEventListener("mousedown", onDocMouseDown);
    document.addEventListener("keydown", onKeyDown);
    window.addEventListener("scroll", close, true);
    window.addEventListener("resize", close);
  }

  return (
    <>
      <button
        ref={triggerEl}
        type="button"
        class="kebab-btn"
        aria-label={props.ariaLabel ?? "Actions"}
        aria-haspopup="true"
        aria-expanded={open()}
        onClick={toggle}
      >
        <span aria-hidden="true">⋮</span>
      </button>
      <Show when={open()}>
        <Portal>
          <div
            ref={menuEl}
            class="kebab-menu"
            role="menu"
            style={{ top: `${pos().top}px`, left: `${pos().left}px` }}
          >
            <For each={props.items}>
              {(item) => (
                <button
                  type="button"
                  role="menuitem"
                  class="kebab-item"
                  classList={{ "kebab-item-danger": item.danger }}
                  disabled={item.disabled}
                  onClick={(e) => {
                    e.stopPropagation();
                    close();
                    item.onSelect();
                  }}
                >
                  {item.label}
                </button>
              )}
            </For>
          </div>
        </Portal>
      </Show>
    </>
  );
}
