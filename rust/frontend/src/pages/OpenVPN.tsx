import { Show, For, createSignal, createResource, onMount } from "solid-js";
import { useSearchParams } from "@solidjs/router";
import {
  getOpenVpnParams,
  generateOpenVpnDh,
  generateOpenVpnTa,
  setupOpenVpnServer,
  listOpenVpnTemplates,
  syncOpenVpnTemplates,
  getOpenVpnTemplate,
  saveOpenVpnTemplate,
  listVpnCerts,
  listOpenVpnProfiles,
  generateOpenVpnProfile,
} from "../api/openvpn";
import { formatDate } from "../utils/dates";
import Spinner from "../components/Spinner";
import SearchInput from "../components/SearchInput";
import AddProfileModal from "../components/AddProfileModal";
import KebabMenu, { type KebabItem } from "../components/KebabMenu";
import SendToVaultDialog from "../components/SendToVaultDialog";
import type {
  CertListItem,
  OpenVpnTemplateItem,
  OpenVpnProfileItem,
} from "../api/types";
import "../styles/pages/openvpn.css";

type Tab = "profiles" | "config";
type ProfileFilter = "all" | "client" | "server";

export default function OpenVPN() {
  const [tab, setTab] = createSignal<Tab>("profiles");
  const [error, setError] = createSignal<string | null>(null);
  const [success, setSuccess] = createSignal<string | null>(null);

  // ── Shared resources (loaded at mount so the Add modal is ready) ──
  const [templates, { refetch: refetchTemplates }] =
    createResource<OpenVpnTemplateItem[]>(listOpenVpnTemplates);
  const [vpnCerts, { refetch: refetchCerts }] =
    createResource<CertListItem[]>(listVpnCerts);

  // ── Configuration tab state ───────────────────────────────────
  // Lazy: getOpenVpnParams reads from 1Password (slow) and is gated on the
  // Configuration tab being open so it doesn't fire on mount and stall the
  // DB-only Profiles query behind the shared connection lock. Re-opening the
  // tab re-fetches (the source toggles false→true again).
  const [params, { refetch: refetchParams }] =
    createResource(() => tab() === "config", getOpenVpnParams);
  const [selectedTemplate, setSelectedTemplate] = createSignal("");
  const [templateContent, setTemplateContent] = createSignal("");
  const [loadingTemplate, setLoadingTemplate] = createSignal(false);
  const [acting, setActing] = createSignal(false);
  const [generatingDh, setGeneratingDh] = createSignal(false);
  const [generatingTa, setGeneratingTa] = createSignal(false);
  const [syncing, setSyncing] = createSignal(false);
  const [newTemplateName, setNewTemplateName] = createSignal("");
  const [showNewTemplate, setShowNewTemplate] = createSignal(false);

  // ── Profiles tab state ────────────────────────────────────────
  const [profiles, { refetch: refetchProfiles }] =
    createResource<OpenVpnProfileItem[]>(listOpenVpnProfiles);
  const [profileSearch, setProfileSearch] = createSignal("");
  const [profileFilter, setProfileFilter] = createSignal<ProfileFilter>("all");
  const [sendTarget, setSendTarget] = createSignal<OpenVpnProfileItem | null>(null);

  // ── Add-profile modal ─────────────────────────────────────────
  const [showAdd, setShowAdd] = createSignal(false);
  const [prefillCn, setPrefillCn] = createSignal("");
  const [prefillSerial, setPrefillSerial] = createSignal<string | null>(null);

  const filteredProfiles = () => {
    const items = profiles() ?? [];
    const q = profileSearch().toLowerCase();
    const f = profileFilter();
    return items.filter((p) => {
      if (f !== "all" && (p.profile_type ?? "").toLowerCase() !== f) return false;
      if (!q) return true;
      return [p.cn, p.created_date ? formatDate(p.created_date) : null].some((v) =>
        v?.toLowerCase().includes(q),
      );
    });
  };

  function switchTab(t: Tab) {
    setTab(t);
    setError(null);
    setSuccess(null);
    if (t === "config") {
      // params re-fetches itself via its tab-gated source; just refresh
      // templates (eagerly loaded, so a manual nudge keeps them current).
      refetchTemplates();
    } else {
      refetchProfiles();
    }
  }

  function openAdd(cn = "", serial: string | null = null) {
    setPrefillCn(cn);
    setPrefillSerial(serial);
    // Refetch both lists on open so a deep-link (page just mounted) doesn't show
    // a modal whose pickers are still loading from the initial mount fetch.
    refetchCerts();
    refetchTemplates();
    setShowAdd(true);
  }

  // Deep link from the cert detail page ("Generate one on the OpenVPN page"):
  // open the Add-profile modal with the cert pre-selected by serial.
  const [searchParams] = useSearchParams();
  onMount(() => {
    if (!searchParams.add && !searchParams.cn) return;
    openAdd(
      (searchParams.cn as string) ?? "",
      (searchParams.serial as string) ?? null,
    );
  });

  // ── Configuration handlers ────────────────────────────────────

  async function handleLoadTemplate(name: string) {
    setSelectedTemplate(name);
    if (!name) {
      setTemplateContent("");
      return;
    }
    setLoadingTemplate(true);
    setError(null);
    try {
      const detail = await getOpenVpnTemplate(name);
      setTemplateContent(detail.content);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoadingTemplate(false);
    }
  }

  async function handleSaveTemplate() {
    const name = selectedTemplate();
    const content = templateContent();
    if (!name) { setError("Select a template first"); return; }
    if (!content.trim()) { setError("Template content is empty"); return; }
    setActing(true);
    setError(null);
    try {
      await saveOpenVpnTemplate(name, content);
      await refetchTemplates();
      setSuccess(`Template '${name}' saved`);
    } catch (e) {
      setError(String(e));
    } finally {
      setActing(false);
    }
  }

  async function handleCreateTemplate() {
    const name = newTemplateName().trim();
    if (!name) { setError("Template name is required"); return; }
    setActing(true);
    setError(null);
    try {
      await setupOpenVpnServer({ template_name: name });
      setShowNewTemplate(false);
      setNewTemplateName("");
      await refetchTemplates();
      refetchParams();
      await handleLoadTemplate(name);
      setSuccess(`Template '${name}' created with server setup`);
    } catch (e) {
      setError(String(e));
    } finally {
      setActing(false);
    }
  }

  async function handleSyncTemplates() {
    setSyncing(true);
    setError(null);
    try {
      const n = await syncOpenVpnTemplates();
      await refetchTemplates();
      setSuccess(`Synced ${n} template(s) from 1Password`);
    } catch (e) {
      setError(String(e));
    } finally {
      setSyncing(false);
    }
  }

  async function handleGenerateDh() {
    setGeneratingDh(true);
    setError(null);
    try {
      await generateOpenVpnDh();
      setSuccess("DH parameters generated");
      refetchParams();
    } catch (e) {
      setError(String(e));
    } finally {
      setGeneratingDh(false);
    }
  }

  async function handleGenerateTa() {
    setGeneratingTa(true);
    setError(null);
    try {
      await generateOpenVpnTa();
      setSuccess("TLS Authentication key generated");
      refetchParams();
    } catch (e) {
      setError(String(e));
    } finally {
      setGeneratingTa(false);
    }
  }

  // ── Profiles handlers ─────────────────────────────────────────

  async function handleRegenerate(profile: OpenVpnProfileItem) {
    if (!profile.template) return;
    setActing(true);
    setError(null);
    setSuccess(null);
    try {
      const result = await generateOpenVpnProfile({
        cn: profile.cn,
        serial: profile.serial,
        template_name: profile.template,
      });
      setSuccess(`Regenerated profile for '${result.cn}' (stored as ${result.title}).`);
      refetchProfiles();
    } catch (e) {
      setError(String(e));
    } finally {
      setActing(false);
    }
  }

  function profileMenuItems(profile: OpenVpnProfileItem): KebabItem[] {
    return [
      { label: "Send to Vault", onSelect: () => setSendTarget(profile) },
      { label: "Regenerate", disabled: !profile.template, onSelect: () => void handleRegenerate(profile) },
    ];
  }

  return (
    <div class="page-openvpn">
      <div class="page-header">
        <h2>OpenVPN Management</h2>
      </div>

      <div class="tab-bar">
        <button
          class={`tab-btn ${tab() === "profiles" ? "tab-active" : ""}`}
          onClick={() => switchTab("profiles")}
        >
          Profiles
        </button>
        <button
          class={`tab-btn ${tab() === "config" ? "tab-active" : ""}`}
          onClick={() => switchTab("config")}
        >
          Configuration
        </button>
      </div>

      {/* ── Profiles Tab ───────────────────────────────────────── */}
      <Show when={tab() === "profiles"}>
        <div class="tab-content">
          <div class="profiles-header">
            <div class="filter-chips">
              <For each={["all", "client", "server"] as ProfileFilter[]}>
                {(f) => (
                  <button
                    class={`chip ${profileFilter() === f ? "chip-active" : ""}`}
                    onClick={() => setProfileFilter(f)}
                  >
                    {f === "all" ? "All" : f === "client" ? "Client" : "Server"}
                  </button>
                )}
              </For>
            </div>
            <div class="profiles-actions">
              <SearchInput value={profileSearch()} onInput={setProfileSearch} />
              <button class="btn-ghost" onClick={() => refetchProfiles()} disabled={profiles.loading}>
                Refresh
              </button>
              <button class="btn-primary" onClick={() => openAdd()}>
                + Add
              </button>
            </div>
          </div>

          <Show when={profiles.loading}>
            <Spinner message="Loading profiles..." />
          </Show>

          <Show when={!profiles.loading && filteredProfiles().length === 0}>
            <p class="text-muted">No VPN profiles found.</p>
          </Show>

          <Show when={filteredProfiles().length > 0}>
            <div class="data-table-wrap">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>CN</th>
                    <th>Serial</th>
                    <th>Template</th>
                    <th>Created</th>
                    <th class="kebab-col"></th>
                  </tr>
                </thead>
                <tbody>
                  <For each={filteredProfiles()}>
                    {(profile) => (
                      <tr class="data-table-row">
                        <td>{profile.profile_type ?? "—"}</td>
                        <td>{profile.cn}</td>
                        <td class="mono">{profile.serial ?? "—"}</td>
                        <td>{profile.template ?? "—"}</td>
                        <td class="mono">{formatDate(profile.created_date)}</td>
                        <td class="kebab-col">
                          <KebabMenu items={profileMenuItems(profile)} />
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </Show>
        </div>
      </Show>

      {/* ── Configuration Tab ──────────────────────────────────── */}
      <Show when={tab() === "config"}>
        <div class="tab-content">
          <Show when={params.loading}>
            <Spinner message="Loading server parameters..." />
          </Show>

          <Show when={params()}>
            {(p) => (
              <div class="server-params">
                <div class="params-grid">
                  <Row label="Hostname" value={p().hostname} mono />
                  <Row label="Port" value={p().port} mono />
                  <Row label="Cipher" value={p().cipher} mono />
                  <Row label="Auth" value={p().auth} mono />
                  <Row
                    label="DH Parameters"
                    value={p().has_dh ? `${p().dh_key_size ?? "?"} bits` : "Not generated"}
                  />
                  <Row
                    label="TLS Auth Key"
                    value={p().has_ta ? `${p().ta_key_size ?? "?"} bits` : "Not generated"}
                  />
                </div>

                <div class="server-actions">
                  <button
                    class="btn-secondary"
                    onClick={handleGenerateDh}
                    disabled={generatingDh() || generatingTa() || p().has_dh}
                  >
                    {generatingDh() ? "Generating..." : "Generate DH"}
                  </button>
                  <button
                    class="btn-secondary"
                    onClick={handleGenerateTa}
                    disabled={generatingDh() || generatingTa() || p().has_ta}
                  >
                    {generatingTa() ? "Generating..." : "Generate TA Key"}
                  </button>
                </div>
              </div>
            )}
          </Show>

          <div class="template-section">
            <div class="template-section-header">
              <h3>Templates</h3>
              <button class="btn-ghost" onClick={handleSyncTemplates} disabled={syncing()}>
                {syncing() ? "Syncing..." : "Refresh"}
              </button>
            </div>
            <div class="template-header">
              <select
                class="form-select"
                value={selectedTemplate()}
                onChange={(e) => handleLoadTemplate(e.currentTarget.value)}
              >
                <option value="">Select template</option>
                <For each={templates()}>
                  {(t) => <option value={t.name}>{t.name}</option>}
                </For>
              </select>
              <button
                class="btn-ghost"
                onClick={() => setShowNewTemplate(!showNewTemplate())}
              >
                New
              </button>
            </div>

            <Show when={showNewTemplate()}>
              <div class="new-template-row">
                <input
                  type="text"
                  placeholder="Template name"
                  value={newTemplateName()}
                  onInput={(e) => setNewTemplateName(e.currentTarget.value)}
                  autocomplete="off"
                  autocorrect="off"
                  autocapitalize="off"
                  spellcheck={false}
                />
                <button
                  class="btn-primary"
                  onClick={handleCreateTemplate}
                  disabled={acting() || !newTemplateName().trim()}
                >
                  {acting() ? "Creating..." : "Create"}
                </button>
                <button
                  class="btn-ghost"
                  onClick={() => { setShowNewTemplate(false); setNewTemplateName(""); }}
                >
                  Cancel
                </button>
              </div>
            </Show>

            <Show when={loadingTemplate()}>
              <Spinner message="Loading template..." />
            </Show>

            <Show when={selectedTemplate()}>
              <textarea
                class="template-editor"
                value={templateContent()}
                onInput={(e) => setTemplateContent(e.currentTarget.value)}
                rows={16}
              />
              <div class="form-actions">
                <button
                  class="btn-primary"
                  onClick={handleSaveTemplate}
                  disabled={acting() || !templateContent().trim()}
                >
                  {acting() ? "Saving..." : "Save Template"}
                </button>
              </div>
            </Show>
          </div>
        </div>
      </Show>

      {/* ── Add-profile modal ──────────────────────────────────── */}
      <AddProfileModal
        open={showAdd()}
        onClose={() => setShowAdd(false)}
        certs={vpnCerts() ?? []}
        certsLoading={vpnCerts.loading}
        templates={templates() ?? []}
        prefillCn={prefillCn()}
        prefillSerial={prefillSerial()}
        onGenerated={() => { refetchProfiles(); setSuccess("VPN profile generated"); }}
      />

      <SendToVaultDialog
        open={!!sendTarget()}
        profile={sendTarget()}
        onClose={() => setSendTarget(null)}
        onDone={(vault) => setSuccess(`Sent ${sendTarget()?.title} to vault '${vault}'`)}
      />

      {/* ── Feedback ───────────────────────────────────────────── */}
      <Show when={error()}>
        <p class="page-error" role="alert">{error()}</p>
      </Show>
      <Show when={success()}>
        <p class="page-success">{success()}</p>
      </Show>

    </div>
  );
}

function Row(props: {
  label: string;
  value: string | null | undefined;
  mono?: boolean;
}) {
  return (
    <div class="detail-row">
      <span class="detail-label">{props.label}</span>
      <span class={`detail-value ${props.mono ? "mono" : ""}`}>
        {props.value ?? "—"}
      </span>
    </div>
  );
}
