import { createSignal, Show, For } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { createCert } from "../api/certs";
import { uploadDbIfPrivateStore } from "../api/ca";
import { CERT_TYPES } from "../api/types";
import "../styles/pages/cert-create.css";

export default function CertCreate() {
  const navigate = useNavigate();
  const [cn, setCn] = createSignal("");
  const [certType, setCertType] = createSignal("device");
  const [keySize, setKeySize] = createSignal<number | undefined>(undefined);
  const [sanInput, setSanInput] = createSignal("");
  const [sans, setSans] = createSignal<string[]>([]);
  const [saving, setSaving] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  function addSan() {
    const value = sanInput().trim();
    if (value && !sans().includes(value)) {
      setSans([...sans(), value]);
      setSanInput("");
    }
  }

  function removeSan(index: number) {
    setSans(sans().filter((_, i) => i !== index));
  }

  async function handleSubmit(e: Event) {
    e.preventDefault();
    if (!cn().trim()) return;

    setSaving(true);
    setError(null);
    try {
      await createCert({
        cn: cn(),
        cert_type: certType(),
        alt_dns_names: sans().length > 0 ? sans() : undefined,
        key_size: keySize(),
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
    <div class="page-cert-create">
      <h2>Create Certificate</h2>

      <form class="create-form" onSubmit={handleSubmit}>
        <div class="form-group">
          <label class="form-label">Common Name</label>
          <input
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
          <label class="form-label">Certificate Type</label>
          <select
            value={certType()}
            onChange={(e) => setCertType(e.currentTarget.value)}
          >
            <For each={CERT_TYPES}>
              {(t) => <option value={t.value}>{t.label}</option>}
            </For>
          </select>
        </div>

        <div class="form-group">
          <label class="form-label">Key Size (optional)</label>
          <select
            value={keySize() ?? ""}
            onChange={(e) => {
              const v = e.currentTarget.value;
              setKeySize(v ? parseInt(v) : undefined);
            }}
          >
            <option value="">Default</option>
            <option value="2048">2048</option>
            <option value="4096">4096</option>
          </select>
        </div>

        <div class="form-group">
          <label class="form-label">Subject Alternative Names</label>
          <div class="san-input-row">
            <input
              type="text"
              placeholder="e.g. alt.example.com"
              value={sanInput()}
              onInput={(e) => setSanInput(e.currentTarget.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") { e.preventDefault(); addSan(); }
              }}
              autocomplete="off"
              autocorrect="off"
              autocapitalize="off"
              spellcheck={false}
            />
            <button type="button" class="btn-ghost" onClick={addSan}>Add</button>
          </div>
          <Show when={sans().length > 0}>
            <div class="san-list">
              <For each={sans()}>
                {(san, i) => (
                  <span class="san-tag">
                    {san}
                    <button type="button" class="san-remove" onClick={() => removeSan(i())}>
                      &times;
                    </button>
                  </span>
                )}
              </For>
            </div>
          </Show>
        </div>

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
