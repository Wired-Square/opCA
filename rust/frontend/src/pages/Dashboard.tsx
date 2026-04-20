import { For, Show, createResource, createSignal } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { appState } from "../stores/app";
import { getDashboard } from "../api/dashboard";
import { generateCrl, uploadCrl } from "../api/crl";
import StatusBubble, { type StatusTone } from "../components/StatusBubble";
import type {
  ActionItem,
  ActionKind,
  DashboardData,
} from "../api/types";
import "../styles/pages/dashboard.css";

function crlStatusLabel(d: DashboardData): string {
  if (!d.crl_present) return "Not generated";
  const level = d.crl_expiry_warning?.level ?? "none";
  switch (level) {
    case "expired":
      return "Expired";
    case "critical":
    case "prominent":
      return "Expires soon";
    default:
      return "Valid";
  }
}

function crlStatusTone(d: DashboardData): StatusTone {
  if (!d.crl_present) return "muted";
  const level = d.crl_expiry_warning?.level ?? "none";
  if (level === "expired" || level === "critical") return "error";
  if (level === "prominent") return "warning";
  return "success";
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [data, { refetch }] = createResource<DashboardData>(getDashboard);
  const [pending, setPending] = createSignal<string | null>(null);
  const [actionError, setActionError] = createSignal<string | null>(null);

  async function runAction(item: ActionItem) {
    setActionError(null);

    const routeMap: Partial<Record<ActionKind, string>> = {
      view_expired_certs: "/certificates?status=expired",
      view_pending_csrs: "/csrs?status=pending",
      view_ca: "/ca",
    };

    const route = routeMap[item.action];
    if (route) {
      navigate(route);
      return;
    }

    setPending(item.id);
    try {
      if (item.action === "regenerate_and_upload_crl") {
        await generateCrl();
        await uploadCrl();
      } else if (item.action === "regenerate_crl") {
        await generateCrl();
      }
      await refetch();
    } catch (e) {
      setActionError(String(e));
    } finally {
      setPending(null);
    }
  }

  return (
    <div class="dashboard">
      <div class="dashboard-header">
        <h2>Dashboard</h2>
        <button class="btn-ghost" onClick={() => refetch()} disabled={data.loading}>
          {data.loading ? "Loading\u2026" : "Refresh"}
        </button>
      </div>

      <Show when={data.error}>
        <p class="dashboard-error">{String(data.error)}</p>
      </Show>

      <Show when={actionError()}>
        <p class="dashboard-error">{actionError()}</p>
      </Show>

      <Show when={appState.vaultState === "empty_vault"}>
        <div class="dashboard-notice">
          <p>No Certificate Authority found in this vault.</p>
          <div class="notice-actions">
            <button class="btn-primary" onClick={() => navigate("/ca")}>
              Initialise CA
            </button>
            <button class="btn-ghost" onClick={() => navigate("/vault?tab=restore")}>
              Restore from Backup
            </button>
          </div>
        </div>
      </Show>

      <Show when={appState.vaultState === "invalid_ca"}>
        <div class="dashboard-notice dashboard-notice-error">
          <p>This vault contains items but no valid Certificate Authority.</p>
          <p class="text-muted">The CA database may be corrupt, or this is not an opCA vault. You may need to restore from a backup using the CLI.</p>
        </div>
      </Show>

      <Show when={data()}>
        {(d) => (
          <>
            <Show when={d().action_items.length > 0}>
              <div class="action-items">
                <For each={d().action_items}>
                  {(item) => (
                    <div class={`action-item action-item--${item.severity}`}>
                      <span class="action-item-dot" aria-hidden="true" />
                      <span class="action-item-message">{item.message}</span>
                      <button
                        class="btn-primary action-item-button"
                        onClick={() => runAction(item)}
                        disabled={pending() === item.id}
                      >
                        {pending() === item.id ? "Working\u2026" : item.button_label}
                      </button>
                    </div>
                  )}
                </For>
              </div>
            </Show>

            <div class="dashboard-grid">
              <div class="stat-card">
                <span class="stat-label">CA Common Name</span>
                <span class="stat-value mono">{d().ca_cn ?? "\u2014"}</span>
              </div>

              <StatusBubble
                label="CA Status"
                status={d().ca_valid ? "Valid" : "Invalid"}
                tone={d().ca_valid ? "success" : "error"}
                detailPrefix="expires"
                detailDate={d().ca_expiry}
                warning={d().ca_expiry_warning}
              />

              <StatusBubble
                label="CRL Status"
                status={crlStatusLabel(d())}
                tone={crlStatusTone(d())}
                detailPrefix="next update"
                detailDate={d().crl_present ? d().crl_next_update : null}
                warning={d().crl_expiry_warning}
              />

              <div
                class="stat-card stat-card-clickable"
                onClick={() => navigate("/csrs?status=pending")}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    navigate("/csrs?status=pending");
                  }
                }}
              >
                <span class="stat-label">Pending CSRs</span>
                <span
                  class="stat-value"
                  classList={{ "text-warning": d().pending_csrs > 0 }}
                >
                  {d().pending_csrs}
                </span>
                <span class="stat-card-detail">awaiting signature</span>
              </div>
            </div>

            <h3 class="section-heading">Certificates</h3>

            <div class="dashboard-grid">
              <div class="stat-card">
                <span class="stat-label">Total</span>
                <span class="stat-value">{d().total_certs}</span>
              </div>
              <div class="stat-card">
                <span class="stat-label">Valid</span>
                <span class="stat-value text-success">{d().valid_certs}</span>
              </div>
              <div class="stat-card">
                <span class="stat-label">Expiring Soon</span>
                <span class="stat-value text-warning">{d().expiring_certs}</span>
              </div>
              <div class="stat-card">
                <span class="stat-label">Expired</span>
                <span class="stat-value text-error">{d().expired_certs}</span>
              </div>
              <div class="stat-card">
                <span class="stat-label">Revoked</span>
                <span class="stat-value text-muted">{d().revoked_certs}</span>
              </div>
            </div>
          </>
        )}
      </Show>

    </div>
  );
}
