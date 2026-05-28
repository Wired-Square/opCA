import { createSignal, Show } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { importCert } from "../api/certs";
import { uploadDbIfPrivateStore } from "../api/ca";
import PemInput from "../components/PemInput";
import "../styles/pages/cert-import.css";

export default function CertImport() {
  const navigate = useNavigate();
  const [certPem, setCertPem] = createSignal("");
  const [keyPem, setKeyPem] = createSignal("");
  const [passphrase, setPassphrase] = createSignal("");
  const [chainPem, setChainPem] = createSignal("");
  const [saving, setSaving] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  function needsPassphrase(): boolean {
    return keyPem().includes("ENCRYPTED");
  }

  async function handleSubmit(e: Event) {
    e.preventDefault();
    setError(null);

    const cert = certPem().trim();
    if (!cert) {
      setError("Certificate PEM is required.");
      return;
    }
    if (!cert.includes("-----BEGIN")) {
      setError("Certificate does not look like PEM-encoded data.");
      return;
    }

    const key = keyPem().trim() || undefined;
    if (!key) {
      setError("Private key is required.");
      return;
    }

    if (needsPassphrase() && !passphrase().trim()) {
      setError("Private key is encrypted. Please provide the passphrase.");
      return;
    }

    setSaving(true);
    try {
      await importCert({
        cert_pem: cert,
        key_pem: key,
        passphrase: passphrase().trim() || undefined,
        chain_pem: chainPem().trim() || undefined,
      });

      // Sync the DB to the private store if one is configured (no prompt;
      // progress shows in the side-nav status), then go to the cert list.
      await uploadDbIfPrivateStore();
      navigate("/certs");
    } catch (err) {
      setError(String(err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div class="page-cert-import">
      <h2>Import Certificate</h2>

      <form class="import-form" onSubmit={handleSubmit}>
        <PemInput
          label="Certificate (required)"
          placeholder="Paste PEM certificate or use Browse..."
          value={certPem()}
          onInput={setCertPem}
          rows={6}
        />

        <PemInput
          label="Private Key (required)"
          placeholder="Paste PEM private key or use Browse..."
          value={keyPem()}
          onInput={setKeyPem}
          rows={6}
        />
        <Show when={needsPassphrase()}>
          <p class="hint-encrypted">Key appears encrypted — passphrase required.</p>
        </Show>

        <div class="form-group">
          <label class="form-label">Passphrase (for encrypted keys)</label>
          <input
            type="password"
            placeholder="Leave blank if key is not encrypted"
            value={passphrase()}
            onInput={(e) => setPassphrase(e.currentTarget.value)}
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            spellcheck={false}
          />
        </div>

        <PemInput
          label="Certificate Chain (optional)"
          placeholder="Paste PEM intermediate CA certificates or use Browse..."
          value={chainPem()}
          onInput={setChainPem}
          rows={4}
        />

        <Show when={error()}>
          <p class="form-error" role="alert">{error()}</p>
        </Show>

        <div class="form-actions">
          <button class="btn-primary" type="submit" disabled={saving() || !certPem().trim()}>
            {saving() ? "Importing\u2026" : "Import Certificate"}
          </button>
          <button class="btn-ghost" type="button" onClick={() => navigate("/certs")}>
            Cancel
          </button>
        </div>
      </form>

    </div>
  );
}
