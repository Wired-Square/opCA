import { Show, For } from "solid-js";
import type { JSX } from "solid-js";
import type { ActionResultController } from "../utils/actionResult";
import PageError from "./PageError";

export interface ResultItem {
  /** Identifier to show for a failed item (serial, CN, or title). */
  id: string;
  ok: boolean;
  error: string | null;
}

type Tone = "neutral" | "success" | "error";

/** The banner chrome: bordered box, headline, Dismiss, optional detail below.
 * Tone drives the border colour and whether assistive tech is alerted. */
function BannerShell(props: {
  tone: Tone;
  headline: JSX.Element;
  onDismiss: () => void;
  children?: JSX.Element;
}) {
  return (
    <div
      class="result-banner"
      classList={{
        "result-banner-error": props.tone === "error",
        "result-banner-success": props.tone === "success",
      }}
      role={props.tone === "error" ? "alert" : undefined}
    >
      <div class="result-banner-head">
        <span>{props.headline}</span>
        <button class="btn-ghost btn-sm" onClick={props.onDismiss}>Dismiss</button>
      </div>
      {props.children}
    </div>
  );
}

/** Summarises a bulk run: a success/failure count plus the failed items and
 * their errors. A count is reported neutrally — it is not an outcome the user
 * should read as simply "good". */
export default function ResultBanner(props: {
  results: ResultItem[];
  onDismiss: () => void;
}) {
  const failures = () => props.results.filter((r) => !r.ok);
  const okCount = () => props.results.filter((r) => r.ok).length;

  return (
    <BannerShell
      tone={failures().length > 0 ? "error" : "neutral"}
      onDismiss={props.onDismiss}
      headline={
        <>
          {okCount()} succeeded
          <Show when={failures().length > 0}>, {failures().length} failed</Show>
        </>
      }
    >
      <Show when={failures().length > 0}>
        <ul class="failure-list">
          <For each={failures()}>
            {(f) => (
              <li>
                <span class="mono">{f.id}</span> — {f.error ?? "failed"}
              </li>
            )}
          </For>
        </ul>
      </Show>
    </BannerShell>
  );
}

/** Reports one action's outcome from `createActionResult` — green when it
 * worked, red with the error beneath when it did not. */
export function ActionResultBanner(props: { outcome: ActionResultController }) {
  return (
    <Show when={props.outcome.result()}>
      {(r) => (
        <BannerShell
          tone={r().error ? "error" : "success"}
          headline={r().summary}
          onDismiss={props.outcome.clear}
        >
          <Show when={r().error}>
            {(error) => <p class="result-banner-detail">{error()}</p>}
          </Show>
        </BannerShell>
      )}
    </Show>
  );
}

/** Inline variant for pages whose established idiom is a message under the
 * form rather than a dismissable banner (the CA tabs). */
export function ActionResultLine(props: { outcome: ActionResultController }) {
  return (
    <Show when={props.outcome.result()}>
      {(r) => (
        <Show
          when={r().error}
          fallback={<p class="form-success">{r().summary}</p>}
        >
          {(error) => (
            <PageError placement="form" message={`${r().summary}: ${error()}`} />
          )}
        </Show>
      )}
    </Show>
  );
}
