import { createSignal, onCleanup, onMount } from "solid-js";
import type { JSX } from "solid-js";
import { Portal } from "solid-js/web";
import { placePopover, type Placement } from "../utils/placePopover";
import "../styles/components/popover.css";

const ITEM = '[role="menuitem"]:not(:disabled), [role="option"]:not([aria-disabled="true"])';

interface PopoverProps {
  anchor: HTMLElement;
  onClose: () => void;
  align?: "start" | "end";
  matchWidth?: boolean;
  focusFirstItem?: boolean;
  role?: JSX.HTMLAttributes<HTMLDivElement>["role"];
  class?: string;
  children: JSX.Element;
}

/** A floating panel pinned to `anchor`, portalled out of any clipping ancestor.
 *  Mount it while open; it dismisses itself through `onClose`. */
export default function Popover(props: PopoverProps) {
  const [placement, setPlacement] = createSignal<Placement | null>(null);
  let panel!: HTMLDivElement;
  let body!: HTMLDivElement;
  let focusInside = false;

  function place() {
    const chrome = panel.offsetHeight - panel.clientHeight;
    setPlacement(
      placePopover(
        props.anchor.getBoundingClientRect(),
        { width: panel.offsetWidth, height: body.offsetHeight + chrome },
        { width: window.innerWidth, height: window.innerHeight },
        { align: props.align ?? "start", matchWidth: !!props.matchWidth },
      ),
    );
  }

  function items() {
    return Array.from(panel.querySelectorAll<HTMLElement>(ITEM));
  }

  function moveFocus(e: KeyboardEvent) {
    const list = items();
    if (list.length === 0) return;
    const at = list.indexOf(document.activeElement as HTMLElement);
    const next = {
      ArrowDown: at < 0 ? 0 : (at + 1) % list.length,
      ArrowUp: at <= 0 ? list.length - 1 : at - 1,
      Home: 0,
      End: list.length - 1,
    }[e.key];
    if (next === undefined) return;
    e.preventDefault();
    list[next].focus();
  }

  function onKeyDown(e: KeyboardEvent) {
    if (e.key !== "Escape") return;
    // Captured on window so a surrounding Modal doesn't also close.
    e.stopPropagation();
    props.onClose();
  }

  function onMouseDown(e: MouseEvent) {
    const t = e.target as Node;
    if (!panel.contains(t) && !props.anchor.contains(t)) props.onClose();
  }

  function onScroll(e: Event) {
    if (!panel.contains(e.target as Node)) props.onClose();
  }

  onMount(() => {
    place();
    const resize = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(place);
    resize?.observe(body);
    if (props.focusFirstItem) items()[0]?.focus();

    window.addEventListener("keydown", onKeyDown, true);
    document.addEventListener("mousedown", onMouseDown);
    window.addEventListener("scroll", onScroll, true);
    window.addEventListener("resize", props.onClose);
    onCleanup(() => {
      resize?.disconnect();
      window.removeEventListener("keydown", onKeyDown, true);
      document.removeEventListener("mousedown", onMouseDown);
      window.removeEventListener("scroll", onScroll, true);
      window.removeEventListener("resize", props.onClose);
      if (focusInside) props.anchor.focus();
    });
  });

  function style(): JSX.CSSProperties {
    const p = placement();
    if (!p) return {};
    return {
      top: `${p.top}px`,
      left: `${p.left}px`,
      "max-height": `${p.maxHeight}px`,
      width: p.width === undefined ? undefined : `${p.width}px`,
    };
  }

  return (
    <Portal>
      <div
        ref={panel}
        class="popover"
        role={props.role}
        style={style()}
        onKeyDown={moveFocus}
        onFocusIn={() => (focusInside = true)}
        onFocusOut={(e) => (focusInside = panel.contains(e.relatedTarget as Node | null))}
        onClick={(e) => e.stopPropagation()}
      >
        <div ref={body} class={props.class}>
          {props.children}
        </div>
      </div>
    </Portal>
  );
}
