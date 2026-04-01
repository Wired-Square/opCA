import { For, Show, createSignal, onMount } from "solid-js";
import { A, useLocation, useNavigate } from "@solidjs/router";
import { getVersion } from "@tauri-apps/api/app";
import { open } from "@tauri-apps/plugin-shell";
import { appState, setAppState, hasCA } from "../../stores/app";
import { availableUpdate, fetchUpdate } from "../../stores/update";
import { operationLabel } from "../../stores/operation";
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
              <span class="update-icon" innerHTML={updateIcon} />
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
                <span class="sidebar-icon" innerHTML={navIcons[item.icon]} aria-hidden="true" />
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
          <span class="sidebar-icon" innerHTML={navIcons.logout} />
          <span class="sidebar-label">Disconnect</span>
        </button>
      </div>
    </aside>
  );
}

const updateIcon = `<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="8"/><polyline points="8 12 12 8 16 12"/></svg>`;

// SVG icons (inline, Lucide-style)
const navIcons: Record<string, string> = {
  dashboard: `<svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>`,
  ca: `<svg viewBox="0 0 24 25"><path d="M12 3L4 7.5v5.5c0 4.94 3.41 9.56 8 10.67 4.59-1.11 8-5.73 8-10.67V7.5L12 3z"/><path d="M9.5 12.5l2 2 3.5-3.5"/></svg>`,
  cert: `<svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="9" y1="13" x2="15" y2="13"/><line x1="9" y1="17" x2="13" y2="17"/></svg>`,
  crl: `<svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="9" y1="15" x2="15" y2="15"/><path d="M15 11l-6 6"/><path d="M9 11l6 6"/></svg>`,
  csr: `<svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="12" x2="12" y2="18"/><line x1="9" y1="15" x2="15" y2="15"/></svg>`,
  dkim: `<svg viewBox="0 0 24 24"><rect x="2" y="4" width="20" height="16" rx="2"/><polyline points="22 4 12 13 2 4"/></svg>`,
  vpn: `<svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><circle cx="12" cy="16" r="1"/></svg>`,
  database: `<svg viewBox="0 0 24 24"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4.03 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4.03 3 9 3s9-1.34 9-3V5"/></svg>`,
  vault: `<svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/><rect x="7" y="7" width="10" height="10" rx="1"/><circle cx="12" cy="12" r="2"/><line x1="12" y1="10" x2="12" y2="7"/></svg>`,
  logout: `<svg viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>`,
};
