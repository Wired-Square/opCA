import type { createFlash } from "@wired-square/kit";
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

/** Flashes and runs `record` only once the write lands; a refused write is dropped, as `CopyButton` drops it. */
export function copyThenRecord(
  flashAfter: ReturnType<typeof createFlash>[1],
  text: string,
  record: () => Promise<void>,
): void {
  flashAfter(writeClipboard(text)).then(record, () => {});
}
