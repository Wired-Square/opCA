import { Show, For } from "solid-js";

export interface BulkResultItem {
  /** Identifier to show for a failed item (serial, CN, or title). */
  id: string;
  ok: boolean;
  error: string | null;
}

interface BulkResultBannerProps {
  results: BulkResultItem[];
  onDismiss: () => void;
}

/** Summarises a bulk run: a success/failure count plus the failed items and
 * their errors. Shared by the Certificates and OpenVPN bulk flows. */
export default function BulkResultBanner(props: BulkResultBannerProps) {
  const failures = () => props.results.filter((r) => !r.ok);
  const okCount = () => props.results.filter((r) => r.ok).length;

  return (
    <div class="bulk-summary" classList={{ "bulk-summary-error": failures().length > 0 }}>
      <div class="bulk-summary-head">
        <span>
          {okCount()} succeeded
          <Show when={failures().length > 0}>, {failures().length} failed</Show>
        </span>
        <button class="btn-ghost btn-sm" onClick={props.onDismiss}>Dismiss</button>
      </div>
      <Show when={failures().length > 0}>
        <ul class="bulk-summary-failures">
          <For each={failures()}>
            {(f) => (
              <li>
                <span class="mono">{f.id}</span> — {f.error ?? "failed"}
              </li>
            )}
          </For>
        </ul>
      </Show>
    </div>
  );
}
