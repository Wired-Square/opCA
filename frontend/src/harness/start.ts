import "@wired-square/mcp-bridge/dom-ops";
import type { Navigator } from "@solidjs/router";
import { chooseScheme, type Scheme } from "@wired-square/kit/core";
import { startHarnessBridge } from "@wired-square/mcp-bridge/tauri-bridge";

let navigate: Navigator;
let stop: Promise<() => void> | undefined;

export function startHarness(nav: Navigator) {
  navigate = nav;
  stop ??= startHarnessBridge({
    navigate: ({ path }) => (navigate(String(path)), {}),
    set_theme: ({ mode }) => (chooseScheme(mode as Scheme), {}),
  });
}

// Solid's HMR re-mounts App, which imports the replaced module and starts a second listener.
import.meta.hot?.dispose(() => stop?.then((unlisten) => unlisten()));
