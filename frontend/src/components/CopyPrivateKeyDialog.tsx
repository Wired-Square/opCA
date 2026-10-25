import { createSignal, createUniqueId, Show } from "solid-js";
import { Confirm } from "@wired-square/kit";
import { generatePassword } from "../api/vault-backup";
import { createActing } from "../utils/acting";

interface CopyPrivateKeyDialogProps {
  open: boolean;
  label: string;
  onClose: () => void;
  onCopy: (passphrase?: string) => Promise<void>;
}

/** Gate on copying a private key to the clipboard, optionally passphrase-encrypted
 * (PKCS#8) by the backend first. Replaces a plugin confirm that existed only
 * because `window.confirm` doesn't block in a webview. */
export default function CopyPrivateKeyDialog(props: CopyPrivateKeyDialogProps) {
  return (
    <Show when={props.open}>
      <CopyPrivateKeyConfirm {...props} />
    </Show>
  );
}

function CopyPrivateKeyConfirm(props: Omit<CopyPrivateKeyDialogProps, "open">) {
  const id = createUniqueId();
  const acting = createActing();
  const [encrypt, setEncrypt] = createSignal(false);
  const [passphrase, setPassphrase] = createSignal("");
  const [confirmation, setConfirmation] = createSignal("");
  const [reveal, setReveal] = createSignal(false);

  const mismatch = () => encrypt() && !!confirmation() && confirmation() !== passphrase();
  const ready = () => !encrypt() || (!!passphrase() && confirmation() === passphrase());

  async function generate() {
    const generated = await generatePassword();
    setPassphrase(generated);
    setConfirmation(generated);
    setReveal(true);
  }

  return (
    <Confirm
      title="Copy Private Key?"
      verb={acting.verb(encrypt() ? "Copy encrypted key" : "Copy", "Copying…")}
      disabled={!ready()}
      onClose={props.onClose}
      act={acting.act(() => props.onCopy(encrypt() ? passphrase() : undefined))}
    >
      <p class="confirm-message">
        Copy the private key for <span class="mono">{props.label}</span> to the clipboard?
        Anything that can read your clipboard (clipboard managers, screen-sharing tools,
        AV/EDR agents, the next app you accidentally paste into) will see the entire key.
        Only do this if you need to install the cert elsewhere, and clear your clipboard
        afterwards.
      </p>
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
    </Confirm>
  );
}
