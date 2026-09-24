import { readFile } from "node:fs/promises";

const HANDOFF = new URL("../target/mcp.json", import.meta.url);
const PROTOCOL_VERSION = "2025-03-26";
const CALL_MS = 30000;

// The server answers each POST as an SSE stream it never closes, so take the
// first `data:` event and cancel.
async function firstMessage(response) {
  if (!response.headers.get("content-type")?.includes("text/event-stream")) return response.json();
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffered = "";
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) throw new Error("MCP stream ended without a message");
      buffered += decoder.decode(value, { stream: true });
      const data = buffered.split("\n").find((line) => line.startsWith("data: {"));
      if (data) return JSON.parse(data.slice("data: ".length));
    }
  } finally {
    await reader.cancel();
  }
}

export async function connect(handoff = process.env.OPCA_MCP_HANDOFF ?? HANDOFF) {
  const { url, token } = JSON.parse(await readFile(handoff, "utf8"));
  const headers = {
    authorization: `Bearer ${token}`,
    accept: "application/json, text/event-stream",
    "content-type": "application/json",
  };
  let nextId = 1;

  async function post(body, ms = CALL_MS) {
    const response = await fetch(url, { method: "POST", headers, body: JSON.stringify(body), signal: AbortSignal.timeout(ms) });
    if (!response.ok) throw new Error(`MCP ${body.method}: HTTP ${response.status} ${await response.text()}`);
    return response;
  }

  async function rpc(method, params, ms) {
    const message = await firstMessage(await post({ jsonrpc: "2.0", id: nextId++, method, params }, ms));
    if (message.error) throw new Error(`MCP ${method}: ${message.error.message}`);
    return message;
  }

  const init = await post({
    jsonrpc: "2.0",
    id: nextId++,
    method: "initialize",
    params: { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: "opca-harness", version: "0" } },
  });
  const session = init.headers.get("mcp-session-id");
  await firstMessage(init);
  if (session) headers["mcp-session-id"] = session;
  await post({ jsonrpc: "2.0", method: "notifications/initialized" });

  async function call(name, args = {}) {
    const { result } = await rpc("tools/call", { name, arguments: args }, CALL_MS + (args.timeout_ms ?? 0));
    const text = result.content?.map((c) => c.text).join("") ?? "";
    if (result.isError) throw new Error(`${name}: ${text}`);
    return result.structuredContent ?? (text ? JSON.parse(text) : {});
  }

  return {
    call,
    query: async (selector) => (await call("query", { selector })).matches,
    click: (selector, index = 0) => call("click", { selector, index }),
    type: (selector, text) => call("type", { selector, text }),
    press: (key, selector) => call("press", selector ? { key, selector } : { key }),
    waitFor: (selector, state = "visible", timeout_ms = 5000) => call("wait_for", { selector, state, timeout_ms }),
    navigate: (path) => call("navigate", { path }),
    setTheme: (mode) => call("set_theme", { mode }),
    resize: (width, height) => call("resize_window", { width, height }),
  };
}
