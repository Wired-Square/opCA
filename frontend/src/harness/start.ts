import type { Navigator } from "@solidjs/router";
import { setThemeMode, type ThemeMode } from "../stores/theme";
import { startHarnessBridge } from "./tauri-bridge";

let navigate: Navigator;
let stop: Promise<() => void> | undefined;

export function startHarness(nav: Navigator) {
  navigate = nav;
  stop ??= startHarnessBridge({
    navigate: ({ path }) => (navigate(String(path)), {}),
    set_theme: ({ mode }) => (setThemeMode(mode as ThemeMode), {}),
  });
}

// Solid's HMR re-mounts App, which imports the replaced module and starts a second listener.
import.meta.hot?.dispose(() => stop?.then((unlisten) => unlisten()));
