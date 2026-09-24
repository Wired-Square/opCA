import { Show, For, createSignal, createMemo, createResource, onMount } from "solid-js";
import { errorMessage } from "../api/tauri";
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
  bulkGenerateOpenVpnProfiles,
  deleteOpenVpnProfile,
  bulkDeleteOpenVpnProfiles,
} from "../api/openvpn";
import { formatDate } from "../utils/dates";
import Spinner from "../components/Spinner";
import SearchInput from "../components/SearchInput";
import AddProfileModal from "../components/AddProfileModal";
import KebabMenu, { type KebabItem } from "../components/KebabMenu";
import SendToVaultDialog from "../components/SendToVaultDialog";
import ConfirmDialog from "../components/ConfirmDialog";
import ResultBanner from "../components/ResultBanner";
import SelectAllCheckbox from "../components/SelectAllCheckbox";
import PageError from "../components/PageError";
import { createSelection } from "../utils/selection";
import type {
  BulkProfileResult,
  CertListItem,
  OpenVpnTemplateItem,
  OpenVpnProfileItem,
  ProfileRef,
  VpnProfileStatus,
} from "../api/types";
import "../styles/pages/openvpn.css";

/** Map a derived profile status to a badge class + label. */
function profileStatusBadge(p: OpenVpnProfileItem): { cls: string; label: string } {
  const status = p.profile_status as VpnProfileStatus | null;
  switch (status) {
    case "needs_regen":
      return {
        cls: "status-expiring",
        label: p.replacement_serial ? `Needs Regen → #${p.replacement_serial}` : "Needs Regen",
      };
    case "revoked": return { cls: "status-revoked", label: "Revoked" };
    case "expired": return { cls: "status-expired", label: "Expired" };
    case "expiring_soon": return { cls: "status-expiring", label: "Expiring Soon" };
    case "current": return { cls: "status-valid", label: "Current" };
    default: return { cls: "status-ignored", label: "—" };
  }
}

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
  // Profiles queued for the Send-to-Vault dialog: one (kebab) or many (bulk).
  const [sendProfiles, setSendProfiles] = createSignal<ProfileRef[] | null>(null);

  // ── Add-profile modal ─────────────────────────────────────────
  const [showAdd, setShowAdd] = createSignal(false);
  const [prefillCn, setPrefillCn] = createSignal("");
  const [prefillSerial, setPrefillSerial] = createSignal<string | null>(null);

  const serialNum = (s: string | null) => (s && Number.isFinite(+s) ? +s : -1);

  // Certs offerable in the Add dialog: the current (highest-serial) cert per CN,
  // dropping CNs that already have a profile (use Regenerate for those) and any
  // replaced/renewed duplicate. The deep-linked CN is always kept so a
  // "Generate one" link can't land on an empty picker.
  const addableCerts = createMemo(() => {
    const taken = new Set((profiles() ?? []).map((p) => p.cn.toLowerCase()));
    const keep = prefillCn().toLowerCase();
    const byCn = new Map<string, CertListItem>();
    for (const c of vpnCerts() ?? []) {
      const cn = c.cn?.toLowerCase();
      if (!cn || (taken.has(cn) && cn !== keep)) continue;
      const cur = byCn.get(cn);
      if (!cur || serialNum(c.serial) > serialNum(cur.serial)) byCn.set(cn, c);
    }
    return [...byCn.values()];
  });

  // Runtime sort: click a column header to set/flip it. Defaults to CN ascending.
  type SortKey = "profile_type" | "cn" | "serial" | "template" | "profile_status" | "created_date";
  const sortColumns: { key: SortKey; label: string }[] = [
    { key: "profile_type", label: "Type" },
    { key: "cn", label: "CN" },
    { key: "serial", label: "Serial" },
    { key: "template", label: "Template" },
    { key: "profile_status", label: "Status" },
    { key: "created_date", label: "Created" },
  ];
  const [sortKey, setSortKey] = createSignal<SortKey>("cn");
  const [sortDir, setSortDir] = createSignal<"asc" | "desc">("asc");

  function toggleSort(key: SortKey) {
    if (sortKey() === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      // Serial and date read most-naturally newest-first; text columns A–Z.
      setSortDir(key === "serial" || key === "created_date" ? "desc" : "asc");
    }
  }
  const sortIndicator = (key: SortKey) =>
    sortKey() === key ? (sortDir() === "asc" ? " ▲" : " ▼") : "";

  function compareProfiles(a: OpenVpnProfileItem, b: OpenVpnProfileItem) {
    const key = sortKey();
    const c =
      key === "serial"
        ? serialNum(a.serial) - serialNum(b.serial)
        : (a[key] ?? "").localeCompare(b[key] ?? "");
    return sortDir() === "asc" ? c : -c;
  }

  const filteredProfiles = () => {
    const items = profiles() ?? [];
    const q = profileSearch().toLowerCase();
    const f = profileFilter();
    return items
      .filter((p) => {
        if (f !== "all" && (p.profile_type ?? "").toLowerCase() !== f) return false;
        if (!q) return true;
        return [p.cn, p.created_date ? formatDate(p.created_date) : null].some((v) =>
          v?.toLowerCase().includes(q),
        );
      })
      .sort(compareProfiles);
  };

  // ── Profile multi-select (keyed by title; auto-clears on profile reload) ──
  const sel = createSelection(filteredProfiles, (p) => p.title, profiles);
  const [bulkResults, setBulkResults] = createSignal<BulkProfileResult[] | null>(null);
  // null = closed; a profile = single delete; "bulk" = bulk delete confirm.
  const [confirmDelete, setConfirmDelete] = createSignal<OpenVpnProfileItem | "bulk" | null>(null);
  const [bulkActing, setBulkActing] = createSignal(false);

  // Regenerate is gated to needs-regen rows that still have a template.
  const canRegenerate = () =>
    sel.selectedItems().length > 0 &&
    sel.selectedItems().every((p) => p.profile_status === "needs_regen" && !!p.template);

  async function handleBulkRegenerate() {
    const items = sel.selectedItems()
      .filter((p) => p.template)
      .map((p) => ({
        cn: p.cn,
        serial: p.replacement_serial ?? p.serial,
        template_name: p.template!,
      }));
    if (items.length === 0) return;
    setBulkActing(true);
    setError(null);
    setSuccess(null);
    try {
      const results = await bulkGenerateOpenVpnProfiles(items);
      setBulkResults(results);
      sel.clear();
      refetchProfiles();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBulkActing(false);
    }
  }

  async function runConfirmDelete() {
    const target = confirmDelete();
    if (target === "bulk") {
      const titles = sel.selectedItems().map((p) => p.title);
      const results = await bulkDeleteOpenVpnProfiles(titles);
      setBulkResults(results);
      sel.clear();
    } else if (target) {
      await deleteOpenVpnProfile(target.title);
      setSuccess(`Deleted VPN profile ${target.title}`);
    }
    refetchProfiles();
  }

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
      setError(errorMessage(e));
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
      setError(errorMessage(e));
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
      setError(errorMessage(e));
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
      setError(errorMessage(e));
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
      setError(errorMessage(e));
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
      setError(errorMessage(e));
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
        // Regenerate against the current valid cert when the profile is stale.
        serial: profile.replacement_serial ?? profile.serial,
        template_name: profile.template,
      });
      setSuccess(`Regenerated profile for '${result.cn}' (stored as ${result.title}).`);
      refetchProfiles();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setActing(false);
    }
  }

  function profileMenuItems(profile: OpenVpnProfileItem): KebabItem[] {
    return [
      { label: "Send to Vault", onSelect: () => setSendProfiles([{ title: profile.title, cn: profile.cn }]) },
      { label: "Regenerate", disabled: !profile.template, onSelect: () => void handleRegenerate(profile) },
      { label: "Delete", danger: true, onSelect: () => setConfirmDelete(profile) },
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

          <Show when={bulkResults()}>
            {(results) => (
              <ResultBanner
                results={results().map((r) => ({ id: r.title ?? r.cn, ok: r.ok, error: r.error }))}
                onDismiss={() => setBulkResults(null)}
              />
            )}
          </Show>

          <Show when={sel.selected().size > 0}>
            <div class="bulk-action-bar">
              <span class="bulk-count">{sel.selected().size} selected</span>
              <button
                class="btn-primary btn-sm"
                disabled={!canRegenerate() || bulkActing()}
                title={canRegenerate() ? undefined : "All selected profiles must be Needs Regen and have a template"}
                onClick={handleBulkRegenerate}
              >
                {bulkActing() ? "Regenerating…" : "Regenerate"}
              </button>
              <button
                class="btn-secondary btn-sm"
                onClick={() => setSendProfiles(sel.selectedItems().map((p) => ({ title: p.title, cn: p.cn })))}
              >
                Send to Vault
              </button>
              <button class="btn-danger btn-sm" onClick={() => setConfirmDelete("bulk")}>Delete</button>
              <button class="btn-ghost btn-sm" onClick={sel.clear}>Clear</button>
            </div>
          </Show>

          <Show when={!profiles.loading && filteredProfiles().length === 0}>
            <p class="text-muted">No VPN profiles found.</p>
          </Show>

          <Show when={filteredProfiles().length > 0}>
            <div class="data-table-wrap">
              <table class="data-table">
                <thead>
                  <tr>
                    <th class="checkbox-col">
                      <SelectAllCheckbox all={sel.allSelected()} some={sel.someSelected()} onToggle={sel.toggleAll} />
                    </th>
                    <For each={sortColumns}>
                      {(col) => (
                        <th class="th-sort" onClick={() => toggleSort(col.key)}>
                          {col.label}{sortIndicator(col.key)}
                        </th>
                      )}
                    </For>
                    <th class="kebab-col"></th>
                  </tr>
                </thead>
                <tbody>
                  <For each={filteredProfiles()}>
                    {(profile) => {
                      const badge = profileStatusBadge(profile);
                      return (
                      <tr
                        class="data-table-row"
                        classList={{ "data-table-row-selected": sel.isSelected(profile.title) }}
                      >
                        <td class="checkbox-col">
                          <input
                            type="checkbox"
                            class="table-checkbox"
                            checked={sel.isSelected(profile.title)}
                            onChange={() => sel.toggle(profile.title)}
                            aria-label={`Select ${profile.cn}`}
                          />
                        </td>
                        <td>{profile.profile_type ?? "—"}</td>
                        <td>{profile.cn}</td>
                        <td class="mono">{profile.serial ?? "—"}</td>
                        <td>{profile.template ?? "—"}</td>
                        <td>
                          <span class={`status-badge ${badge.cls}`}>{badge.label}</span>
                        </td>
                        <td class="mono">{formatDate(profile.created_date)}</td>
                        <td class="kebab-col">
                          <KebabMenu items={profileMenuItems(profile)} />
                        </td>
                      </tr>
                      );
                    }}
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
        certs={addableCerts()}
        certsLoading={vpnCerts.loading}
        templates={templates() ?? []}
        prefillCn={prefillCn()}
        prefillSerial={prefillSerial()}
        // The modal stays open and reports the outcome itself (count and
        // verb aware), so the page must not announce it a second time.
        onGenerated={() => refetchProfiles()}
      />

      <SendToVaultDialog
        open={!!sendProfiles()}
        profiles={sendProfiles() ?? []}
        onClose={() => setSendProfiles(null)}
        onDone={(vault, sent) => {
          const what = sent.length === 1 ? sent[0].title : `${sent.length} profiles`;
          setSuccess(`Sent ${what} to vault '${vault}'`);
          sel.clear();
        }}
      />

      <ConfirmDialog
        open={!!confirmDelete()}
        title="Delete VPN Profile"
        message={
          confirmDelete() === "bulk"
            ? `Remove ${sel.selectedItems().length} profile(s) from the list? The stored .ovpn document(s) stay in the vault.`
            : `Remove the profile for ${(confirmDelete() as OpenVpnProfileItem | null)?.cn ?? "this CN"} from the list? The stored .ovpn document stays in the vault.`
        }
        confirmLabel="Delete"
        actingLabel="Deleting…"
        danger
        onClose={() => setConfirmDelete(null)}
        onConfirm={runConfirmDelete}
      />

      {/* ── Feedback ───────────────────────────────────────────── */}
      <PageError message={error()} />
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
