import { Show, createSignal, createResource, For } from "solid-js";
import { getLogContents, getLogPath } from "../api/logs";
import { createCopiedSignal } from "../utils/clipboard";
import Spinner from "../components/Spinner";
import "../styles/pages/log.css";

/** Classify a log line by its level for colour coding. */
function logLevel(line: string): string {
  if (line.includes("[ERROR]")) return "error";
  if (line.includes("[WARN]")) return "warn";
  if (line.includes("[INFO]")) return "info";
  return "debug";
}

export default function Log() {
  const [contents, { refetch }] = createResource(getLogContents);
  const [logPath] = createResource(getLogPath);
  const [copied, markCopied] = createCopiedSignal();
  const [autoScroll, setAutoScroll] = createSignal(true);

  let scrollRef: HTMLPreElement | undefined;

  function copyAll() {
    const text = contents();
    if (text) {
      navigator.clipboard.writeText(text);
      markCopied();
    }
  }

  function handleRefresh() {
    refetch();
    if (autoScroll() && scrollRef) {
      requestAnimationFrame(() => {
        scrollRef!.scrollTop = scrollRef!.scrollHeight;
      });
    }
  }

  // Scroll to bottom on initial load
  function onContentMount(el: HTMLPreElement) {
    scrollRef = el;
    if (autoScroll()) {
      requestAnimationFrame(() => {
        el.scrollTop = el.scrollHeight;
      });
    }
  }

  const lines = () => contents()?.split("\n") ?? [];

  return (
    <div class="page-log">
      <div class="page-header">
        <h2>Application Log</h2>
        <div class="header-actions">
          <button class="btn-ghost" onClick={handleRefresh} disabled={contents.loading}>
            {contents.loading ? "Loading\u2026" : "Refresh"}
          </button>
        </div>
      </div>

      <Show when={logPath()}>
        <div class="log-path">{logPath()}</div>
      </Show>

      <Show when={!contents.loading} fallback={<Spinner message="Loading log\u2026" />}>
        <Show when={contents()} fallback={<p class="text-muted">No log file found.</p>}>
          <div class="log-viewer">
            <pre class="log-content" ref={onContentMount}>
              <For each={lines()}>
                {(line) => (
                  <span class={`log-line log-level-${logLevel(line)}`}>{line}{"\n"}</span>
                )}
              </For>
            </pre>
            <div class="log-toolbar">
              <span class="line-count">{lines().length} lines</span>
              <label>
                <input
                  type="checkbox"
                  checked={autoScroll()}
                  onChange={(e) => setAutoScroll(e.currentTarget.checked)}
                />{" "}
                Auto-scroll
              </label>
              <button class="btn-ghost btn-sm" onClick={copyAll}>
                {copied() ? "Copied" : "Copy all"}
              </button>
            </div>
          </div>
        </Show>
      </Show>
    </div>
  );
}
