import { Show, For } from "solid-js";
import { Notice, type Action } from "@wired-square/kit";

export interface ResultItem {
  /** Identifier to show for a failed item (serial, CN, or title). */
  id: string;
  ok: boolean;
  error: string | null;
}

/** Summarises a bulk run: a count, reported neutrally rather than as "good", plus each failed item and its error. */
export default function ResultBanner(props: {
  results: ResultItem[];
  onDismiss: () => void;
}) {
  const failures = () => props.results.filter((r) => !r.ok);
  const okCount = () => props.results.length - failures().length;

  return (
    <Notice tone={failures().length > 0 ? "bad" : "neutral"}>
      <div class="notice-head">
        <span>
          {okCount()} succeeded
          <Show when={failures().length > 0}>, {failures().length} failed</Show>
        </span>
        <button class="btn-ghost btn-sm" onClick={props.onDismiss}>Dismiss</button>
      </div>
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
    </Notice>
  );
}

export function ActionOutcome(props: { action: Pick<Action, "failed" | "succeeded"> }) {
  return (
    <>
      <Notice tone="good">{props.action.succeeded()}</Notice>
      <Notice tone="bad">{props.action.failed()}</Notice>
    </>
  );
}
