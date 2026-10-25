import { createSignal } from "solid-js";
import { Refusal } from "@wired-square/kit";
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
