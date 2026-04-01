import { Show, For, createSignal, createResource } from "solid-js";
import {
  getOpenVpnParams,
  generateOpenVpnDh,
  generateOpenVpnTa,
  setupOpenVpnServer,
  listOpenVpnTemplates,
  getOpenVpnTemplate,
  saveOpenVpnTemplate,
  listVpnClients,
  generateOpenVpnProfile,
  listOpenVpnProfiles,
  sendProfileToVault,
} from "../api/openvpn";
import { formatDate } from "../utils/dates";
import Spinner from "../components/Spinner";
import SearchInput from "../components/SearchInput";
import VaultPicker from "../components/VaultPicker";
import type {
  OpenVpnServerParams,
  OpenVpnTemplateItem,
  OpenVpnProfileItem,
} from "../api/types";
import "../styles/pages/openvpn.css";

type Tab = "client" | "server" | "profiles";

export default function OpenVPN() {
  const [tab, setTab] = createSignal<Tab>("profiles");
  const [error, setError] = createSignal<string | null>(null);
  const [success, setSuccess] = createSignal<string | null>(null);

  // ── Server tab state ──────────────────────────────────────────
  const [params, { refetch: refetchParams }] =
    createResource<OpenVpnServerParams>(getOpenVpnParams);
  const [templates, { refetch: refetchTemplates }] =
    createResource<OpenVpnTemplateItem[]>(listOpenVpnTemplates);
  const [selectedTemplate, setSelectedTemplate] = createSignal("");
  const [templateContent, setTemplateContent] = createSignal("");
  const [loadingTemplate, setLoadingTemplate] = createSignal(false);
  const [acting, setActing] = createSignal(false);
  const [generatingDh, setGeneratingDh] = createSignal(false);
  const [generatingTa, setGeneratingTa] = createSignal(false);
  const [newTemplateName, setNewTemplateName] = createSignal("");
  const [showNewTemplate, setShowNewTemplate] = createSignal(false);

  // ── Client tab state ──────────────────────────────────────────
  const [vpnClients, { refetch: refetchClients }] =
    createResource<string[]>(listVpnClients);
  const [clientTemplate, setClientTemplate] = createSignal("");
  const [clientCn, setClientCn] = createSignal("");
  const [clientDestVault, setClientDestVault] = createSignal("");
  const [generatedProfile, setGeneratedProfile] = createSignal<OpenVpnProfileItem | null>(null);
  const [sendingProfile, setSendingProfile] = createSignal(false);

  // ── Profiles tab state ────────────────────────────────────────
  const [profiles, { refetch: refetchProfiles }] =
    createResource<OpenVpnProfileItem[]>(listOpenVpnProfiles);
  const [profileSearch, setProfileSearch] = createSignal("");
  const [selectedProfile, setSelectedProfile] = createSignal<OpenVpnProfileItem | null>(null);
  const [destVault, setDestVault] = createSignal("");

  const filteredProfiles = () => {
    const items = profiles() ?? [];
    const q = profileSearch().toLowerCase();
    if (!q) return items;
    return items.filter((p) =>
      [p.cn, p.created_date ? formatDate(p.created_date) : null].some((v) => v?.toLowerCase().includes(q))
    );
  };

  function switchTab(t: Tab) {
    setTab(t);
    setError(null);
    setSuccess(null);
    if (t === "server") {
      refetchParams();
      refetchTemplates();
    } else if (t === "client") {
      refetchTemplates();
      refetchClients();
    } else if (t === "profiles") {
      refetchProfiles();
    }
  }

  // ── Server handlers ───────────────────────────────────────────

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

  // ── Client handlers ───────────────────────────────────────────

  async function handleGenerateProfile() {
    const tmpl = clientTemplate();
    const cn = clientCn();
    if (!tmpl && !cn) { setError("Please select a template and a VPN client before generating a profile."); setSuccess(null); return; }
    if (!tmpl) { setError("Please select a template before generating a profile."); setSuccess(null); return; }
    if (!cn) { setError("Please select a VPN client before generating a profile."); setSuccess(null); return; }
    setActing(true);
    setError(null);
    setGeneratedProfile(null);
    try {
      const profile = await generateOpenVpnProfile({ cn, template_name: tmpl });
      setGeneratedProfile(profile);
      setSuccess(`Profile generated for '${cn}'`);
      setClientCn("");
      setClientDestVault("");
    } catch (e) {
      setError(String(e));
    } finally {
      setActing(false);
    }
  }

  async function handleSendGeneratedProfile() {
    const profile = generatedProfile();
    const vault = clientDestVault().trim();
    if (!profile || !vault) return;
    setSendingProfile(true);
    setError(null);
    try {
      await sendProfileToVault(profile.cn, vault);
      setSuccess(`Sent VPN_${profile.cn} to vault '${vault}'`);
      setGeneratedProfile(null);
      setClientDestVault("");
    } catch (e) {
      setError(String(e));
    } finally {
      setSendingProfile(false);
    }
  }

  // ── Profiles handlers ─────────────────────────────────────────

  async function handleSendToVault() {
    const profile = selectedProfile();
    const vault = destVault().trim();
    if (!profile) { setError("Select a profile from the table"); return; }
    if (!vault) { setError("Enter a destination vault"); return; }
    setActing(true);
    setError(null);
    try {
      await sendProfileToVault(profile.cn, vault);
      setSuccess(`Sent VPN_${profile.cn} to vault '${vault}'`);
    } catch (e) {
      setError(String(e));
    } finally {
      setActing(false);
    }
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
          class={`tab-btn ${tab() === "client" ? "tab-active" : ""}`}
          onClick={() => switchTab("client")}
        >
          Client
        </button>
        <button
          class={`tab-btn ${tab() === "server" ? "tab-active" : ""}`}
          onClick={() => switchTab("server")}
        >
          Server
        </button>
      </div>

      {/* ── Client Tab ─────────────────────────────────────────── */}
      <Show when={tab() === "client"}>
        <div class="tab-content">
          <div class="form-group">
            <label class="form-label">Template</label>
            <select
              class="form-select"
              value={clientTemplate()}
              onChange={(e) => setClientTemplate(e.currentTarget.value)}
            >
              <option value="">Select template</option>
              <For each={templates()}>
                {(t) => <option value={t.name}>{t.name}</option>}
              </For>
            </select>
          </div>

          <div class="form-group">
            <label class="form-label">Client CN</label>
            <Show when={vpnClients.loading}>
              <Spinner message="Loading VPN clients..." small />
            </Show>
            <select
              class="form-select"
              value={clientCn()}
              onChange={(e) => setClientCn(e.currentTarget.value)}
            >
              <option value="">Select VPN client</option>
              <For each={vpnClients()}>
                {(cn) => <option value={cn}>{cn}</option>}
              </For>
            </select>
          </div>

          <div class="form-actions">
            <button
              class="btn-primary"
              onClick={handleGenerateProfile}
              disabled={acting()}
            >
              {acting() ? "Generating..." : "Generate Profile"}
            </button>
          </div>

          <Show when={generatedProfile()}>
            {(profile) => (
              <div class="generated-profile-section">
                <p class="page-success">
                  Profile generated for '{profile().cn}' (stored as {profile().title})
                </p>
                <div class="form-group">
                  <label class="form-label">Send to vault (optional)</label>
                  <VaultPicker value={clientDestVault()} onChange={setClientDestVault} />
                </div>
                <div class="form-actions">
                  <button
                    class="btn-primary"
                    onClick={handleSendGeneratedProfile}
                    disabled={sendingProfile() || !clientDestVault().trim()}
                  >
                    {sendingProfile() ? "Sending..." : "Send to Vault"}
                  </button>
                </div>
              </div>
            )}
          </Show>
        </div>
      </Show>

      {/* ── Server Tab ─────────────────────────────────────────── */}
      <Show when={tab() === "server"}>
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
            <h3>Templates</h3>
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

      {/* ── Profiles Tab ───────────────────────────────────────── */}
      <Show when={tab() === "profiles"}>
        <div class="tab-content">
          <div class="profiles-header">
            <SearchInput value={profileSearch()} onInput={setProfileSearch} />
            <button class="btn-ghost" onClick={() => refetchProfiles()} disabled={profiles.loading}>
              Refresh
            </button>
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
                    <th>CN</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={filteredProfiles()}>
                    {(profile) => (
                      <tr
                        class={`data-table-row ${selectedProfile()?.cn === profile.cn ? "data-table-row-selected" : ""}`}
                        onClick={() => setSelectedProfile(profile)}
                      >
                        <td>{profile.cn}</td>
                        <td class="mono">{formatDate(profile.created_date)}</td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </Show>

          <Show when={selectedProfile()}>
            <div class="send-section">
              <div class="form-group">
                <label class="form-label">Destination vault</label>
                <VaultPicker value={destVault()} onChange={setDestVault} />
              </div>
              <div class="form-actions">
                <button
                  class="btn-primary"
                  onClick={handleSendToVault}
                  disabled={acting() || !destVault().trim()}
                >
                  {acting() ? "Sending..." : "Send to Vault"}
                </button>
              </div>
            </div>
          </Show>
        </div>
      </Show>

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
        {props.value ?? "\u2014"}
      </span>
    </div>
  );
}
