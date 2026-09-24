import { createSignal, onCleanup } from "solid-js";
import type { Accessor } from "solid-js";

/** The outcome of a single user action. `error` is null on success. */
export interface ActionResult {
  summary: string;
  error: string | null;
}

/** How long a successful result stays on screen. */
export const SUCCESS_DISMISS_MS = 4000;

export interface ActionResultController {
  result: Accessor<ActionResult | null>;
  /** Record an outcome. Omit `error` (or pass null) for success; a caught
   *  value is coerced to a string here so call sites need not. */
  report: (summary: string, error?: unknown) => void;
  clear: () => void;
}

/**
 * Reactive result of a mutating action, for pages that need to tell the user
 * whether it worked.
 *
 * A success clears itself after a few seconds; a failure persists so the error
 * stays readable until dismissed. The timer is cleaned up on unmount, and a
 * second `report()` cancels the first one's pending clear.
 *
 * Holds state only — render it through `ResultBanner` or inline
 * `ActionResultLine`, whichever matches the page.
 */
export function createActionResult(): ActionResultController {
  const [result, setResult] = createSignal<ActionResult | null>(null);
  let timer: number | undefined;

  const clear = () => {
    clearTimeout(timer);
    setResult(null);
  };

  const report = (summary: string, error?: unknown) => {
    clearTimeout(timer);
    const message = error == null ? null : String(error);
    setResult({ summary, error: message });
    if (!message) timer = window.setTimeout(() => setResult(null), SUCCESS_DISMISS_MS);
  };

  onCleanup(() => clearTimeout(timer));

  return { result, report, clear };
}
