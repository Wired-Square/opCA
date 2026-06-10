import { Show, For, createSignal, createMemo, createEffect } from "solid-js";
import Modal from "./Modal";
import VpnClientPicker from "./VpnClientPicker";
import SendToVault from "./SendToVault";
import {
  getVpnProfileForCn,
  generateOpenVpnProfile,
  bulkGenerateOpenVpnProfiles,
  addOpenVpnProfileEntries,
} from "../api/openvpn";
import type {
  BulkProfileResult,
  CertListItem,
  OpenVpnTemplateItem,
  OpenVpnProfileItem,
} from "../api/types";

interface AddProfileModalProps {
  open: boolean;
  onClose: () => void;
  /** Valid VPN certificates (client + server) for the picker. */
  certs: CertListItem[];
  certsLoading: boolean;
  /** Templates for the dropdown (DB-backed, so already loaded). */
  templates: OpenVpnTemplateItem[];
  /** Pre-selected cert when opened from a deep-link. */
  prefillCn?: string;
  prefillSerial?: string | null;
  /** Called after a profile is generated so the list behind the modal refetches. */
  onGenerated: () => void;
}

/** Friendly Client/Server label from a cert's type. */
function typeLabel(certType: string | null | undefined): string | null {
  if (!certType) return null;
  if (certType.toLowerCase() === "vpnclient") return "Client";
  if (certType.toLowerCase() === "vpnserver") return "Server";
  return certType;
}

/**
 * Create-VPN-profile(s) modal. The user picks one or more VPN certificates and a
 * single template; one profile is generated per cert (the cert's type is
 * inferred). A single pick keeps the optional "send to vault" follow-up; picking
 * several runs the bulk generate and reports a per-cert summary.
 */
export default function AddProfileModal(props: AddProfileModalProps) {
  const [selected, setSelected] = createSignal<Set<string>>(new Set());
  const [template, setTemplate] = createSignal("");
  const [genNow, setGenNow] = createSignal(true);
  const [generated, setGenerated] = createSignal<OpenVpnProfileItem | null>(null);
  const [bulkResults, setBulkResults] = createSignal<BulkProfileResult[] | null>(null);
  const [resultVerb, setResultVerb] = createSignal<"generated" | "added">("generated");
  const [acting, setActing] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  const selectedCerts = createMemo(() =>
    props.certs.filter((c) => c.serial && selected().has(c.serial)),
  );

  // Hint under the picker: the inferred type for a single pick, else a count.
  const hint = () => {
    const certs = selectedCerts();
    if (certs.length === 1) {
      const t = typeLabel(certs[0]?.cert_type);
      return t ? `Profile type: ${t}` : null;
    }
    return certs.length > 1 ? `${certs.length} certificates selected` : null;
  };

  function toggleCert(cert: CertListItem) {
    if (!cert.serial) return;
    setSelected((s) => {
      const n = new Set(s);
      n.has(cert.serial!) ? n.delete(cert.serial!) : n.add(cert.serial!);
      return n;
    });
    setError(null);
    // When this pick is the first one, default the template to the one last
    // used for its CN.
    if (cert.cn && selected().size === 1 && selected().has(cert.serial!)) {
      void preselectTemplate(cert.cn);
    }
  }

  // Reset / apply prefill on each open transition. Kept free of any
  // props.templates read so it only re-runs when `open` flips.
  let lastOpen = false;
  createEffect(() => {
    const open = props.open;
    if (open && !lastOpen) {
      setError(null);
      setGenerated(null);
      setBulkResults(null);
      setGenNow(true);
      setTemplate("");
      setSelected(props.prefillSerial ? new Set([props.prefillSerial]) : new Set<string>());
      if (props.prefillCn) void preselectTemplate(props.prefillCn);
    }
    lastOpen = open;
  });

  // Default the template to the first available once templates load, if nothing
  // is selected yet (handles a deep-link open where templates were still loading).
  createEffect(() => {
    if (props.open && !template() && props.templates.length > 0) {
      setTemplate(props.templates[0].name);
    }
  });

  /** Default the template to the one last used for this CN, if any. */
  async function preselectTemplate(forCn: string) {
    try {
      const prior = await getVpnProfileForCn(forCn);
      if (prior?.template) setTemplate(prior.template);
    } catch {
      // Non-fatal — keep whatever default is set.
    }
  }

  async function handleAdd() {
    const tmpl = template();
    const certs = selectedCerts();
    if (!tmpl) { setError("Select a template first."); return; }
    if (certs.length === 0) { setError("Select at least one VPN certificate."); return; }
    setActing(true);
    setError(null);
    const items = certs.map((c) => ({ cn: c.cn ?? "", serial: c.serial, template_name: tmpl }));
    try {
      if (!genNow()) {
        // Register the rows without producing documents — generate later.
        setResultVerb("added");
        setBulkResults(await addOpenVpnProfileEntries(items));
      } else if (items.length === 1) {
        // A single generate keeps the optional send-to-vault follow-up.
        setGenerated(await generateOpenVpnProfile(items[0]));
      } else {
        setResultVerb("generated");
        setBulkResults(await bulkGenerateOpenVpnProfiles(items));
      }
      props.onGenerated();
    } catch (e) {
      setError(String(e));
    } finally {
      setActing(false);
    }
  }

  const isForm = () => !generated() && !bulkResults();

  return (
    <Modal open={props.open} onClose={props.onClose} title="Add VPN Profile">
      {/* Single result — offer the optional send-to-vault follow-up. */}
      <Show when={generated()}>
        {(profile) => (
          <div class="add-profile-done">
            <p class="page-success">
              Profile generated for '{profile().cn}' (stored as {profile().title}).
            </p>
            <SendToVault
              profiles={[{ title: profile().title, cn: profile().cn }]}
              label="Send to vault (optional)"
              onDone={(_v, { sent }) => { if (sent.length > 0) props.onClose(); }}
            >
              <button class="btn-ghost" onClick={props.onClose}>Done</button>
            </SendToVault>
          </div>
        )}
      </Show>

      {/* Multiple results — per-cert summary. */}
      <Show when={bulkResults()}>
        {(results) => {
          const succeeded = () => results().filter((r) => r.ok);
          const failed = () => results().filter((r) => !r.ok);
          // Sending only applies to generated documents, not not-yet-generated rows.
          const canSend = () => resultVerb() === "generated" && succeeded().length > 0;
          const doneButton = <button class="btn-ghost" onClick={props.onClose}>Done</button>;
          return (
            <div class="add-profile-done">
              <p class="page-success">
                {succeeded().length} profile(s) {resultVerb()}
                <Show when={failed().length > 0}>, {failed().length} failed</Show>.
              </p>
              <Show when={failed().length > 0}>
                <ul class="bulk-summary-failures">
                  <For each={failed()}>
                    {(f) => <li><span class="mono">{f.cn}</span> — {f.error ?? "failed"}</li>}
                  </For>
                </ul>
              </Show>
              <Show when={canSend()} fallback={<div class="form-actions">{doneButton}</div>}>
                <SendToVault
                  profiles={succeeded().map((r) => ({ title: r.title ?? "", cn: r.cn }))}
                  label="Send all to vault (optional)"
                >
                  {doneButton}
                </SendToVault>
              </Show>
            </div>
          );
        }}
      </Show>

      <Show when={isForm()}>
        <div class="form-group">
          <label class="form-label">VPN Certificate</label>
          <VpnClientPicker
            selected={selected()}
            clients={props.certs}
            loading={props.certsLoading}
            onToggle={toggleCert}
          />
          <Show when={hint()}>
            {(text) => <p class="form-hint">{text()}</p>}
          </Show>
        </div>

        <div class="form-group">
          <label class="form-label">Template</label>
          <select
            class="form-select"
            value={template()}
            onChange={(e) => setTemplate(e.currentTarget.value)}
          >
            <option value="">Select template</option>
            <For each={props.templates}>
              {(t) => <option value={t.name}>{t.name}</option>}
            </For>
          </select>
        </div>

        <label class="form-check">
          <input
            type="checkbox"
            checked={genNow()}
            onChange={(e) => setGenNow(e.currentTarget.checked)}
          />
          <span>Generate Profile</span>
        </label>

        <Show when={error()}>
          <p class="page-error" role="alert">{error()}</p>
        </Show>

        <div class="form-actions">
          <button class="btn-primary" onClick={handleAdd} disabled={acting()}>
            {acting() ? (genNow() ? "Generating..." : "Adding...") : "Add"}
          </button>
          <button class="btn-ghost" onClick={props.onClose}>Cancel</button>
        </div>
      </Show>
    </Modal>
  );
}
