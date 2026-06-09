import { Show, For, createSignal, createMemo, createEffect } from "solid-js";
import Modal from "./Modal";
import VpnClientPicker from "./VpnClientPicker";
import VaultPicker from "./VaultPicker";
import {
  getVpnProfileForCn,
  generateOpenVpnProfile,
  sendProfileToVault,
} from "../api/openvpn";
import type {
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
 * Create-a-VPN-profile modal. The user picks a VPN certificate (client or
 * server); the profile's type is inferred from the cert. The template dropdown
 * preselects the one last used for that CN (else the first available).
 */
export default function AddProfileModal(props: AddProfileModalProps) {
  const [cn, setCn] = createSignal("");
  const [serial, setSerial] = createSignal<string | null>(null);
  const [template, setTemplate] = createSignal("");
  const [destVault, setDestVault] = createSignal("");
  const [generated, setGenerated] = createSignal<OpenVpnProfileItem | null>(null);
  const [acting, setActing] = createSignal(false);
  const [sending, setSending] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  // The cert backing the current selection, for the inferred type label.
  const selectedCert = createMemo(
    () =>
      props.certs.find((c) => c.serial === serial() && c.cn === cn())
      ?? props.certs.find((c) => c.cn === cn())
      ?? null,
  );

  // Reset / apply prefill on each open transition. Kept free of any
  // props.templates read so it only re-runs when `open` flips.
  let lastOpen = false;
  createEffect(() => {
    const open = props.open;
    if (open && !lastOpen) {
      setError(null);
      setGenerated(null);
      setDestVault("");
      setTemplate("");
      setCn(props.prefillCn ?? "");
      setSerial(props.prefillSerial ?? null);
      if (props.prefillCn) void preselectTemplate(props.prefillCn);
    }
    lastOpen = open;
  });

  // Default the template to the first available once templates load, if nothing
  // is selected yet. This handles a deep-link open where the templates resource
  // is still loading when the modal appears (and the picker would otherwise
  // stay empty until reopened).
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

  function selectCert(nextCn: string, nextSerial: string | null) {
    setCn(nextCn);
    setSerial(nextSerial);
    setError(null);
    if (nextCn) void preselectTemplate(nextCn);
  }

  async function handleGenerate() {
    const tmpl = template();
    const targetCn = cn();
    if (!tmpl) { setError("Select a template before generating a profile."); return; }
    if (!targetCn) { setError("Select a VPN certificate before generating a profile."); return; }
    setActing(true);
    setError(null);
    try {
      const profile = await generateOpenVpnProfile({
        cn: targetCn,
        serial: serial(),
        template_name: tmpl,
      });
      setGenerated(profile);
      props.onGenerated();
    } catch (e) {
      setError(String(e));
    } finally {
      setActing(false);
    }
  }

  async function handleSend() {
    const profile = generated();
    const vault = destVault().trim();
    if (!profile || !vault) return;
    setSending(true);
    setError(null);
    try {
      await sendProfileToVault(profile.title, profile.cn, vault);
      setDestVault("");
      props.onClose();
    } catch (e) {
      setError(String(e));
    } finally {
      setSending(false);
    }
  }

  return (
    <Modal open={props.open} onClose={props.onClose} title="Add VPN Profile">
      <Show
        when={!generated()}
        fallback={
          <div class="add-profile-done">
            <p class="page-success">
              Profile generated for '{generated()!.cn}' (stored as {generated()!.title}).
            </p>
            <div class="form-group">
              <label class="form-label">Send to vault (optional)</label>
              <VaultPicker value={destVault()} onChange={setDestVault} />
            </div>
            <div class="form-actions">
              <button
                class="btn-primary"
                onClick={handleSend}
                disabled={sending() || !destVault().trim()}
              >
                {sending() ? "Sending..." : "Send to Vault"}
              </button>
              <button class="btn-ghost" onClick={props.onClose}>Done</button>
            </div>
          </div>
        }
      >
        <div class="form-group">
          <label class="form-label">VPN Certificate</label>
          <VpnClientPicker
            value={cn()}
            serial={serial()}
            clients={props.certs}
            loading={props.certsLoading}
            onChange={selectCert}
          />
          <Show when={typeLabel(selectedCert()?.cert_type)}>
            {(label) => <p class="form-hint">Profile type: {label()}</p>}
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

        <Show when={error()}>
          <p class="page-error" role="alert">{error()}</p>
        </Show>

        <div class="form-actions">
          <button class="btn-primary" onClick={handleGenerate} disabled={acting()}>
            {acting() ? "Generating..." : "Generate Profile"}
          </button>
          <button class="btn-ghost" onClick={props.onClose}>Cancel</button>
        </div>
      </Show>
    </Modal>
  );
}
