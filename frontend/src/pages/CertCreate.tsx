import { createSignal, Show, For } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { createCert } from "../api/certs";
import { CERT_TYPES, defaultKeyAlgorithm, type KeyAlgorithm } from "../api/types";
import KeyAlgorithmSelect from "../components/KeyAlgorithmSelect";
import SanInput from "../components/SanInput";
import "../styles/pages/cert-create.css";

export default function CertCreate() {
  const navigate = useNavigate();
  const [cn, setCn] = createSignal("");
  const [certType, setCertType] = createSignal("webserver");
  const [keyAlgorithm, setKeyAlgorithm] = createSignal<KeyAlgorithm>(defaultKeyAlgorithm("webserver"));
  const [sans, setSans] = createSignal<string[]>([]);
  const [saving, setSaving] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  async function handleSubmit(e: Event) {
    e.preventDefault();
    if (!cn().trim()) return;

    setSaving(true);
    setError(null);
    try {
      await createCert({
        cn: cn(),
        cert_type: certType(),
        alt_names: sans().length > 0 ? sans() : undefined,
        key_algorithm: keyAlgorithm(),
      });
      // create_cert already persisted the DB (1Password + private store), so
      // just return to the list.
      navigate("/certs");
    } catch (err) {
      setError(String(err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div class="page-cert-create">
      <h2>Create Certificate</h2>

      <form class="create-form" onSubmit={handleSubmit}>
        <div class="form-group">
          <label class="form-label" for="cert-cn">Common Name</label>
          <input
            id="cert-cn"
            type="text"
            placeholder="e.g. server.example.com"
            value={cn()}
            onInput={(e) => setCn(e.currentTarget.value)}
            autofocus
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            spellcheck={false}
          />
        </div>

        <div class="form-group">
          <label class="form-label" for="cert-type">Certificate Type</label>
          <select
            id="cert-type"
            value={certType()}
            onChange={(e) => setCertType(e.currentTarget.value)}
          >
            <For each={CERT_TYPES}>
              {(t) => <option value={t.value}>{t.label}</option>}
            </For>
          </select>
        </div>

        <KeyAlgorithmSelect value={keyAlgorithm()} onChange={setKeyAlgorithm} />

        <SanInput values={sans()} onChange={setSans} />

        <Show when={error()}>
          <p class="form-error" role="alert">{error()}</p>
        </Show>

        <div class="form-actions">
          <button class="btn-primary" type="submit" disabled={saving() || !cn().trim()}>
            {saving() ? "Creating\u2026" : "Create Certificate"}
          </button>
          <button class="btn-ghost" type="button" onClick={() => navigate("/certs")}>
            Cancel
          </button>
        </div>
      </form>

    </div>
  );
}
