import { createEffect, createSignal, createUniqueId, Show } from "solid-js";
import ConfirmDialog from "./ConfirmDialog";
import { generatePassword } from "../api/vault-backup";

/** Gate on copying a private key to the clipboard, optionally passphrase-encrypted
 * (PKCS#8) by the backend first. Replaces a plugin confirm that existed only
 * because `window.confirm` doesn't block in a webview. */
export default function CopyPrivateKeyDialog(props: {
  open: boolean;
  label: string;
  onClose: () => void;
  onCopy: (passphrase?: string) => Promise<void>;
}) {
  const id = createUniqueId();
  const [encrypt, setEncrypt] = createSignal(false);
  const [passphrase, setPassphrase] = createSignal("");
  const [confirmation, setConfirmation] = createSignal("");
  const [reveal, setReveal] = createSignal(false);

  createEffect(() => {
    if (props.open) {
      setEncrypt(false);
      setPassphrase("");
      setConfirmation("");
      setReveal(false);
    }
  });

  const mismatch = () => encrypt() && !!confirmation() && confirmation() !== passphrase();
  const ready = () => !encrypt() || (!!passphrase() && confirmation() === passphrase());

  async function generate() {
    const generated = await generatePassword();
    setPassphrase(generated);
    setConfirmation(generated);
    setReveal(true);
  }

  return (
    <ConfirmDialog
      open={props.open}
      title="Copy Private Key?"
      message={
        <>
          Copy the private key for <span class="mono">{props.label}</span> to the clipboard?
          Anything that can read your clipboard (clipboard managers, screen-sharing tools,
          AV/EDR agents, the next app you accidentally paste into) will see the entire key.
          Only do this if you need to install the cert elsewhere, and clear your clipboard
          afterwards.
        </>
      }
      confirmLabel={encrypt() ? "Copy encrypted key" : "Copy"}
      actingLabel="Copying…"
      danger
      canConfirm={ready}
      onClose={props.onClose}
      onConfirm={() => props.onCopy(encrypt() ? passphrase() : undefined)}
    >
      <label class="checkbox-row">
        <input type="checkbox" checked={encrypt()} onChange={(e) => setEncrypt(e.currentTarget.checked)} />
        Encrypt with a passphrase
      </label>
      <Show when={encrypt()}>
        <div class="form-group">
          <label class="form-label" for={`${id}-pass`}>Passphrase</label>
          <div class="san-input-row">
            <input
              id={`${id}-pass`}
              type={reveal() ? "text" : "password"}
              value={passphrase()}
              onInput={(e) => setPassphrase(e.currentTarget.value)}
              autocomplete="new-password"
              autofocus
            />
            <button type="button" class="btn-ghost" onClick={generate}>Generate</button>
          </div>
        </div>
        <div class="form-group">
          <label class="form-label" for={`${id}-confirm`}>Confirm passphrase</label>
          <input
            id={`${id}-confirm`}
            type={reveal() ? "text" : "password"}
            value={confirmation()}
            onInput={(e) => setConfirmation(e.currentTarget.value)}
            aria-invalid={mismatch() ? "true" : undefined}
            aria-describedby={`${id}-hint`}
            autocomplete="new-password"
          />
          <p id={`${id}-hint`} class="form-hint" classList={{ "is-invalid": mismatch() }} aria-live="polite">
            {mismatch()
              ? "✗ Passphrases don't match"
              : "opCA doesn't store this passphrase. Keep it somewhere safe; the key can't be opened without it."}
          </p>
        </div>
        <label class="checkbox-row">
          <input type="checkbox" checked={reveal()} onChange={(e) => setReveal(e.currentTarget.checked)} />
          Show passphrase
        </label>
      </Show>
    </ConfirmDialog>
  );
}
