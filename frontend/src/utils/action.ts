import { createSignal } from "solid-js";
import type { Accessor } from "solid-js";
import type { ActionResultController } from "./actionResult";

/**
 * Headlines for one run.
 *
 * `success` can read what the body returned, and `failure` is resolved after
 * the body too — so it can describe how far a partial failure got. Omit
 * `success` when the action navigates away and the destination reports for
 * itself.
 */
export interface ActionMessages<T> {
  success?: string | ((result: T) => string);
  failure: string | (() => string);
}

export interface Action {
  /** True while a run is in flight — for the button label and disabled state. */
  busy: Accessor<boolean>;
  /** Run `fn` and report the outcome. Never throws, so whatever used to sit in
   *  `finally` is just the code after the await. */
  run: <T>(messages: ActionMessages<T>, fn: () => Promise<T>) => Promise<void>;
}

/**
 * One mutating action: its in-flight flag, and the clear/try/report dance
 * every one of them was writing out by hand.
 *
 * Holds state only — the outcome surfaces through whichever `ResultBanner`
 * renderer the page already uses. One per action rather than one per page, so
 * `busy()` disables just the button that is working.
 */
export function createAction(outcome: ActionResultController): Action {
  const [busy, setBusy] = createSignal(false);

  async function run<T>(messages: ActionMessages<T>, fn: () => Promise<T>) {
    setBusy(true);
    outcome.clear();
    try {
      const result = await fn();
      const { success } = messages;
      if (success) outcome.report(typeof success === "string" ? success : success(result));
    } catch (e) {
      const { failure } = messages;
      outcome.report(typeof failure === "string" ? failure : failure(), e);
    } finally {
      setBusy(false);
    }
  }

  return { busy, run };
}
