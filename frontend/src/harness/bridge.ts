import { emit, listen } from "@tauri-apps/api/event";
import { errorMessage } from "../api/tauri";
import type { Navigator } from "@solidjs/router";
import { setThemeMode, type ThemeMode } from "../stores/theme";
import { runDomOp } from "./domOps";

type Args = Record<string, any>;

let navigate: Navigator;
let unlisten: Promise<() => void> | undefined;

const appOps: Record<string, (args: Args) => unknown> = {
  navigate: ({ path }) => (navigate(path), {}),
  set_theme: ({ mode }) => (setThemeMode(mode as ThemeMode), {}),
};

export function startHarnessBridge(nav: Navigator) {
  navigate = nav;
  unlisten ??= listen<{ id: number; op: string; args: Args }>("harness:request", async ({ payload: { id, op, args } }) => {
    try {
      const run = appOps[op];
      emit("harness:reply", { id, ok: await (run ? run(args) : runDomOp(op, args)) });
    } catch (e) {
      emit("harness:reply", { id, error: errorMessage(e) });
    }
  });
}

// Solid's HMR re-mounts App, which imports the replaced module and starts a second listener.
import.meta.hot?.dispose(() => unlisten?.then((stop) => stop()));
