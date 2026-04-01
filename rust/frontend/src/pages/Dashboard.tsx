import { Show, createResource } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { appState } from "../stores/app";
import { getDashboard } from "../api/dashboard";
import { formatDate } from "../utils/dates";
import TzToggle from "../components/TzToggle";
import type { DashboardData } from "../api/types";
import "../styles/pages/dashboard.css";

export default function Dashboard() {
  const navigate = useNavigate();
  const [data, { refetch }] = createResource<DashboardData>(getDashboard);

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
            <div class="dashboard-grid">
              <div class="stat-card">
                <span class="stat-label">CA Status</span>
                <span class="stat-value">
                  <Show when={d().ca_valid} fallback={<span class="text-warning">Invalid</span>}>
                    <span class="text-success">Valid</span>
                  </Show>
                </span>
              </div>
              <div class="stat-card">
                <span class="stat-label">CA Common Name</span>
                <span class="stat-value mono">{d().ca_cn ?? "\u2014"}</span>
              </div>
              <div class="stat-card">
                <span class="stat-label">CA Expiry <TzToggle /></span>
                <span class="stat-value mono">{formatDate(d().ca_expiry)}</span>
              </div>
              <div class="stat-card">
                <span class="stat-label">Vault</span>
                <span class="stat-value mono">{appState.vault}</span>
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
