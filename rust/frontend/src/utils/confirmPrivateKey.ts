/**
 * Block the private-key copy flow until the user explicitly confirms. The
 * clipboard is a wide-open broadcast surface — clipboard managers, screen
 * sharing apps, AV/EDR agents, and pasted-into-the-wrong-app history can
 * all leak the key — so the wording is deliberately heavy.
 *
 * Uses the Tauri dialog plugin rather than `window.confirm`, which can be
 * non-blocking inside a webview and led to a bug where Cancel still let the
 * copy proceed. The plugin returns a real Promise<boolean>.
 *
 * CA private keys are blocked at the UI layer (the indicator never offers
 * the copy action) and refused server-side; this dialog covers leaf certs
 * (CA-issued and external).
 */
export async function confirmPrivateKeyCopy(label: string): Promise<boolean> {
  const { confirm } = await import("@tauri-apps/plugin-dialog");
  const message =
    `Copy the private key for "${label}" to the clipboard?\n\n` +
    `This is a sensitive secret. Anything that can read your clipboard ` +
    `(clipboard managers, screen-sharing tools, AV/EDR agents, the next ` +
    `app you accidentally paste into) will see the entire key.\n\n` +
    `Only do this if you genuinely need to install the cert elsewhere ` +
    `and have somewhere safe to paste it. Clear your clipboard afterwards.`;
  return await confirm(message, {
    title: "Copy Private Key?",
    kind: "warning",
    okLabel: "Copy",
    cancelLabel: "Cancel",
  });
}
