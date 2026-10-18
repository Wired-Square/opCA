// The page half of wslib-mcp's `tauri-bridge`. Vendored byte-for-byte from
// wslib-rs `crates/wslib-mcp/js/tauri-bridge.ts`, beside `dom-ops.ts`; the
// Rust side holds the same text as `wslib_mcp::tauri_bridge::BRIDGE_TS`.

import { emit, listen, type UnlistenFn } from "@tauri-apps/api/event";
import { runDomOp } from "./dom-ops";

export type HarnessArgs = Record<string, unknown>;

export interface HarnessRequest {
  id: number;
  op: string;
  args: HarnessArgs;
}

export type HarnessReply = { id: number; ok: unknown } | { id: number; error: string };

/** Ops only the app can answer, such as `navigate`; tried before the DOM ops. */
export type AppOps = Record<string, (args: HarnessArgs) => unknown>;

export async function answer({ id, op, args }: HarnessRequest, appOps: AppOps = {}): Promise<HarnessReply> {
  try {
    const run = Object.prototype.hasOwnProperty.call(appOps, op) ? appOps[op] : undefined;
    return { id, ok: await (run ? run(args) : runDomOp(op, args)) };
  } catch (error) {
    return { id, error: error instanceof Error ? error.message : String(error) };
  }
}

export function startHarnessBridge(appOps: AppOps = {}): Promise<UnlistenFn> {
  return listen<HarnessRequest>("harness:request", async ({ payload }) => {
    await emit("harness:reply", await answer(payload, appOps));
  });
}
