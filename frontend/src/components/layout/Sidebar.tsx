import { For, Show, createSignal, onMount } from "solid-js";
import { A, useLocation, useNavigate } from "@solidjs/router";
import { getVersion } from "@tauri-apps/api/app";
import { open } from "@tauri-apps/plugin-shell";
import { appState, setAppState, hasCA } from "../../stores/app";
import { availableUpdate, fetchUpdate } from "../../stores/update";
import { operationLabel } from "../../stores/operation";
import Icon from "../Icon";
import "../../styles/components/sidebar.css";

interface NavItem {
  label: string;
  path: string;
  icon: string;
  /** When true, this item requires an initialised CA. */
  gated?: boolean;
}

const navItems: NavItem[] = [
  { label: "Dashboard", path: "/dashboard", icon: "dashboard", gated: true },
  { label: "CA", path: "/ca", icon: "ca" },
  { label: "Certificates", path: "/certs", icon: "cert", gated: true },
  { label: "CRL", path: "/crl", icon: "crl", gated: true },
  { label: "CSR", path: "/csr", icon: "csr", gated: true },
  { label: "DKIM", path: "/dkim", icon: "dkim", gated: true },
  { label: "OpenVPN", path: "/openvpn", icon: "vpn", gated: true },
  { label: "Database", path: "/database", icon: "database", gated: true },
  { label: "Vault", path: "/vault", icon: "vault" },
  { label: "Log", path: "/log", icon: "log" },
];

export default function Sidebar() {
  const location = useLocation();
  const navigate = useNavigate();
  const [version, setVersion] = createSignal("");

  onMount(async () => {
    try {
      setVersion(await getVersion());
    } catch {
      // Ignore — version display is non-critical
    }
    fetchUpdate();
  });

  function handleLogout() {
    setAppState({
      connected: false,
      vaultState: "disconnected",
      vault: "",
      account: null,
    });
    navigate("/");
  }

  return (
    <aside class="sidebar">
      <div class="sidebar-brand">
        <div class="sidebar-brand-row">
          <img src="/logo.svg" alt="" class="sidebar-logo" />
          <span class="brand-name">
            <span class="brand-op">op</span>
            <span class="brand-ca">CA</span>
          </span>
          <span class="brand-version">v{version()}</span>
        </div>
        <span class="brand-byline">by Wired Square</span>
        <Show when={availableUpdate()}>
          {(update) => (
            <button
              class="update-badge"
              onClick={() => open(update().url)}
              title={`Update available: ${update().version}`}
            >
              <span class="update-icon"><Icon name="update" /></span>
              Update available
            </button>
          )}
        </Show>
      </div>
      <nav class="sidebar-nav">
        <For each={navItems}>
          {(item) => {
            const disabled = () =>
              appState.vaultState === "invalid_ca" ||
              (item.gated && !hasCA());
            return (
              <A
                href={disabled() ? "#" : item.path}
                class="sidebar-link"
                classList={{
                  active: location.pathname.startsWith(item.path),
                  disabled: disabled(),
                }}
                onClick={(e: MouseEvent) => {
                  if (disabled()) e.preventDefault();
                }}
              >
                <span class="sidebar-icon" aria-hidden="true"><Icon name={item.icon} /></span>
                <span class="sidebar-label">{item.label}</span>
              </A>
            );
          }}
        </For>
      </nav>
      <div class="sidebar-footer">
        <Show when={operationLabel()}>
          {(label) => (
            <div class="sidebar-status" aria-live="polite" aria-atomic="true">
              <span class="sidebar-status-spinner" aria-hidden="true" />
              <span class="sidebar-status-label">{label()}</span>
            </div>
          )}
        </Show>
        <button class="sidebar-link logout-btn" onClick={handleLogout}>
          <span class="sidebar-icon"><Icon name="logout" /></span>
          <span class="sidebar-label">Disconnect</span>
        </button>
      </div>
    </aside>
  );
}

