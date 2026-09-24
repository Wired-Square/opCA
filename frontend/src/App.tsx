import { Show, createEffect, onMount, type ParentProps } from "solid-js";
import { useLocation, useNavigate } from "@solidjs/router";
import { appState } from "./stores/app";
import { initOperationListener } from "./stores/operation";
import Sidebar from "./components/layout/Sidebar";
import Header from "./components/layout/Header";
import RouteErrorBoundary from "./components/RouteErrorBoundary";
import "./styles/pages/app.css";

/** Routes accessible when the vault is empty (no CA). */
const EMPTY_VAULT_ROUTES = ["/", "/ca", "/vault", "/log"];

export default function App(props: ParentProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const isConnectPage = () => location.pathname === "/" || location.pathname === "";

  onMount(() => {
    initOperationListener();
    if (import.meta.env.DEV) import("./harness/bridge").then((m) => m.startHarnessBridge(navigate));
  });

  // Redirect based on vault state
  createEffect(() => {
    if (!appState.connected) return;

    const path = location.pathname;
    const state = appState.vaultState;

    if (state === "valid_ca") {
      // All routes allowed
      return;
    }

    if (state === "invalid_ca") {
      // Only dashboard (shows error message), connect, and log pages allowed
      if (path !== "/" && path !== "/dashboard" && path !== "/log") {
        navigate("/dashboard", { replace: true });
      }
      return;
    }

    // empty_vault: only allow CA, Vault, and connect
    if (
      !EMPTY_VAULT_ROUTES.some(
        (r) => path === r || (r !== "/" && path.startsWith(r + "/"))
      )
    ) {
      navigate("/ca", { replace: true });
    }
  });

  // Inside the layout, so a page crash leaves the sidebar and header usable.
  const outlet = () => <RouteErrorBoundary>{props.children}</RouteErrorBoundary>;

  return (
    <Show when={!isConnectPage()} fallback={outlet()}>
      <Sidebar />
      <div class="main-area">
        <Header />
        <main class="content">{outlet()}</main>
      </div>

    </Show>
  );
}
