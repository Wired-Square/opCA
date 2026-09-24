import { createSignal, onCleanup } from "solid-js";
import type { Accessor } from "solid-js";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";

/**
 * Write text to the system clipboard via the Tauri clipboard-manager plugin.
 *
 * Goes through native IPC rather than `navigator.clipboard`, so it does not
 * depend on the document holding a fresh user-activation gesture or having
 * focus — crucial after a native confirm dialog or any `await` between the
 * click and the write (Tauri WKWebView otherwise rejects the write with
 * `NotAllowedError`).
 */
export const writeClipboard = (text: string): Promise<void> => writeText(text);

/**
 * Reactive "copied" signal that auto-resets after a timeout,
 * with proper cleanup on component unmount.
 */
export function createCopiedSignal(ms = 2000): [Accessor<boolean>, () => void] {
  const [copied, setCopied] = createSignal(false);
  let timer: number | undefined;

  const trigger = () => {
    setCopied(true);
    clearTimeout(timer);
    timer = window.setTimeout(() => setCopied(false), ms);
  };

  onCleanup(() => clearTimeout(timer));

  return [copied, trigger];
}
