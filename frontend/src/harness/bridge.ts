import { emit, listen } from "@tauri-apps/api/event";
import { errorMessage } from "../api/tauri";
import type { Navigator } from "@solidjs/router";
import { setThemeMode, type ThemeMode } from "../stores/theme";

type Args = Record<string, any>;
type Box = Pick<DOMRect, "left" | "top" | "right" | "bottom">;

const TEXT_CAP = 200;
const POLL_MS = 50;
const EPSILON = 0.5;

function contains(outer: Box, inner: Box): boolean {
  return (
    inner.left >= outer.left - EPSILON &&
    inner.top >= outer.top - EPSILON &&
    inner.right <= outer.right + EPSILON &&
    inner.bottom <= outer.bottom + EPSILON
  );
}

export function rectInViewport(r: Box, width: number, height: number): boolean {
  return contains({ left: 0, top: 0, right: width, bottom: height }, r);
}

function clips(el: Element): boolean {
  const style = getComputedStyle(el);
  return [style.overflow, style.overflowX, style.overflowY].some((o) => o && o !== "visible");
}

export function clippingAncestor(el: Element): Element | null {
  const rect = el.getBoundingClientRect();
  for (let a = el.parentElement; a && a !== document.documentElement; a = a.parentElement) {
    if (clips(a) && !contains(a.getBoundingClientRect(), rect)) return a;
  }
  return null;
}

export function describe(el: Element): string {
  const id = el.id ? `#${el.id}` : "";
  const classes = [...el.classList].map((c) => `.${c}`).join("");
  return el.tagName.toLowerCase() + id + classes;
}

function isVisible(el: Element): boolean {
  const r = el.getBoundingClientRect();
  return (r.width > 0 || r.height > 0) && getComputedStyle(el).visibility !== "hidden";
}

function pick(selector: string, index = 0): HTMLElement {
  const matches = document.querySelectorAll<HTMLElement>(selector);
  const el = matches[index];
  if (!el) throw new Error(`${matches.length} match(es) for ${selector}; no index ${index}`);
  return el;
}

function query({ selector }: Args) {
  const matches = [...document.querySelectorAll(selector)].map((el) => {
    const r = el.getBoundingClientRect();
    const clippedBy = clippingAncestor(el);
    return {
      text: ((el as HTMLElement).innerText ?? el.textContent ?? "").trim().slice(0, TEXT_CAP),
      role: el.getAttribute("role"),
      ariaLabel: el.getAttribute("aria-label"),
      rect: { x: r.x, y: r.y, width: r.width, height: r.height },
      inViewport: rectInViewport(r, window.innerWidth, window.innerHeight),
      clippedBy: clippedBy && describe(clippedBy),
    };
  });
  return { matches };
}

function click({ selector, index }: Args) {
  const el = pick(selector, index);
  const r = el.getBoundingClientRect();
  const at = { bubbles: true, cancelable: true, clientX: r.x + r.width / 2, clientY: r.y + r.height / 2 };
  el.dispatchEvent(new PointerEvent("pointerdown", at));
  el.dispatchEvent(new MouseEvent("mousedown", at));
  el.focus();
  el.dispatchEvent(new PointerEvent("pointerup", at));
  el.dispatchEvent(new MouseEvent("mouseup", at));
  el.dispatchEvent(new MouseEvent("click", at));
  return {};
}

function type({ selector, text }: Args) {
  const el = pick(selector) as HTMLInputElement;
  el.focus();
  el.value = text;
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
  return {};
}

function press({ key, selector }: Args) {
  const el = selector ? pick(selector) : (document.activeElement ?? document.body);
  el.dispatchEvent(new KeyboardEvent("keydown", { key, bubbles: true, cancelable: true }));
  el.dispatchEvent(new KeyboardEvent("keyup", { key, bubbles: true, cancelable: true }));
  return {};
}

async function waitFor({ selector, state, timeout_ms }: Args) {
  const started = performance.now();
  const met = () => {
    const shown = [...document.querySelectorAll(selector)].some(isVisible);
    return state === "gone" ? !shown : shown;
  };
  while (!met()) {
    if (performance.now() - started > timeout_ms) throw new Error(`${selector} not ${state} after ${timeout_ms} ms`);
    await new Promise((resolve) => setTimeout(resolve, POLL_MS));
  }
  return { elapsedMs: Math.round(performance.now() - started) };
}

let navigate: Navigator;
let unlisten: Promise<() => void> | undefined;

const ops: Record<string, (args: Args) => unknown> = {
  navigate: ({ path }) => (navigate(path), {}),
  set_theme: ({ mode }) => (setThemeMode(mode as ThemeMode), {}),
  query,
  click,
  type,
  press,
  wait_for: waitFor,
};

export function startHarnessBridge(nav: Navigator) {
  navigate = nav;
  unlisten ??= listen<{ id: number; op: string; args: Args }>("harness:request", async ({ payload: { id, op, args } }) => {
    try {
      const run = ops[op];
      if (!run) throw new Error(`unknown harness op ${op}`);
      emit("harness:reply", { id, ok: await run(args) });
    } catch (e) {
      emit("harness:reply", { id, error: errorMessage(e) });
    }
  });
}

// Solid's HMR re-mounts App, which imports the replaced module and starts a second listener.
import.meta.hot?.dispose(() => unlisten?.then((stop) => stop()));
