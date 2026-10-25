import { createSignal } from "solid-js";
import { Refusal, refusalMessage } from "@wired-square/kit";
import { errorMessage } from "../api/tauri";

/** A kit `Confirm`'s verb that reads `busy` while its act runs, and the act's failure shown as written. */
export function createActing() {
  const [acting, setActing] = createSignal(false);
  return {
    verb: (idle: string, busy: string) => (acting() ? busy : idle),
    act:
      <A extends unknown[]>(run: (...args: A) => Promise<unknown> | void) =>
      async (...args: A) => {
        setActing(true);
        try {
          await run(...args);
        } catch (e) {
          throw e instanceof Refusal ? e : new Refusal(errorMessage(e));
        } finally {
          setActing(false);
        }
      },
  };
}

/** `act` for a kit action's `run`, its failure read as `headline: reason`; `headline` is read after `act` fails. */
export function headed<R>(headline: string | (() => string), act: () => Promise<R>) {
  return async () => {
    try {
      return await act();
    } catch (e) {
      throw new Refusal(`${typeof headline === "string" ? headline : headline()}: ${errorMessage(e)}`);
    }
  };
}

/** A load's failure for a `Notice`, and nothing while it has none. */
export const failureOf = (error: unknown) => (error == null ? undefined : refusalMessage(error));
