// Phase 8 running-app walk: every shared-Popover surface, in both themes.
// Never selects a mutating menu item; dialogs are opened and dismissed unsent.
import { connect } from "./mcp.mjs";

const SHORT = { width: 900, height: 600 };
const PANEL = ".popover";
const DIALOG = '[role="dialog"]';
const EPSILON = 0.5;

class Skip extends Error {}
const skip = (why) => {
  throw new Skip(why);
};
const assert = (ok, message) => {
  if (!ok) throw new Error(message);
};
const bottom = (r) => r.y + r.height;

const app = await connect();
const results = [];

async function check(name, run) {
  try {
    results.push({ status: "PASS", name, detail: (await run()) ?? "" });
  } catch (e) {
    results.push({ status: e instanceof Skip ? "SKIP" : "FAIL", name, detail: e.message });
    await dismissAll();
  }
}

async function dismissAll() {
  for (const selector of [PANEL, DIALOG]) {
    if ((await app.query(selector)).length === 0) continue;
    await app.press("Escape");
    await app.waitFor(selector, "gone", 2000).catch(() => {});
  }
}

async function indexOfText(selector, text) {
  const index = (await app.query(selector)).findIndex((m) => m.text === text);
  assert(index >= 0, `no ${selector} reading "${text}"`);
  return index;
}

async function visit(path, ready) {
  await app.navigate(path);
  await app.waitFor(ready, "visible", 15000);
  await app.waitFor(".content .spinner", "gone", 30000);
}

// Opens a popover and checks it floats clear of its anchor, inside the viewport and unclipped.
async function openPanel({ trigger, index = 0, anchor = trigger, anchorIndex = index }) {
  const anchorBox = (await app.query(anchor))[anchorIndex];
  assert(anchorBox, `no anchor ${anchor}[${anchorIndex}]`);
  await app.click(trigger, index);
  await app.waitFor(PANEL);
  await app.waitFor(`${PANEL} .spinner`, "gone", 20000);
  const [panel] = await app.query(PANEL);
  assert(panel.inViewport, `panel leaves the viewport at ${JSON.stringify(panel.rect)}`);
  assert(!panel.clippedBy, `panel clipped by ${panel.clippedBy}`);
  const below = panel.rect.y >= bottom(anchorBox.rect) - EPSILON;
  const above = bottom(panel.rect) <= anchorBox.rect.y + EPSILON;
  assert(below || above, "panel overlaps its anchor");
  return { panel, anchor: anchorBox, side: below ? "below" : "above" };
}

async function escapeCloses(stillOpen) {
  await app.press("Escape");
  await app.waitFor(PANEL, "gone", 2000);
  if (stillOpen) assert((await app.query(stillOpen)).length > 0, `Escape also closed ${stillOpen}`);
}

async function lastVisibleKebab() {
  const kebabs = await app.query(".data-table-row .kebab-btn");
  const index = kebabs.findLastIndex((k) => k.inViewport && !k.clippedBy);
  if (index < 0) skip("no rows");
  return index;
}

async function bottomRowKebab(page, ready) {
  await visit(page, ready);
  const index = await lastVisibleKebab();
  const { panel, anchor, side } = await openPanel({ trigger: ".data-table-row .kebab-btn", index });
  const items = await app.query(`${PANEL} [role="menuitem"]`);
  assert(items.every((i) => i.inViewport && !i.clippedBy), "a menu item is off-screen or clipped");
  await escapeCloses();
  const roomBelow = SHORT.height - bottom(anchor.rect);
  if (roomBelow > panel.rect.height + 12) skip(`opened ${side}; last row ends ${Math.round(roomBelow)}px above the bottom — too few rows to force the flip`);
  assert(side === "above", `opened ${side} with ${Math.round(roomBelow)}px below`);
  return `opened above, ${items.length} items`;
}

async function walk(theme) {
  await app.setTheme(theme);
  const t = (name) => `[${theme}] ${name}`;

  await check(t("Certs: bottom-row kebab opens upward"), () => bottomRowKebab("/certs", ".data-table"));

  await check(t("Certs: kebab closes on outside mousedown"), async () => {
    await visit("/certs", ".data-table");
    await openPanel({ trigger: ".data-table-row .kebab-btn" });
    await app.click(".page-header h2");
    await app.waitFor(PANEL, "gone", 2000);
  });

  await check(t("CertInfo: header kebab"), async () => {
    const { certs } = await app.call("list_certs");
    const serial = certs.find((c) => c.serial)?.serial;
    if (!serial) skip("no certificate with a serial");
    const trigger = '.kebab-btn[aria-label="Certificate actions"]';
    await visit(`/certs/${serial}`, trigger);
    const { side } = await openPanel({ trigger });
    await escapeCloses();
    return `opened ${side}`;
  });

  await check(t("OpenVPN: bottom-row kebab opens upward"), () => bottomRowKebab("/openvpn", ".profiles-header"));

  await check(t("OpenVPN: VaultPicker in Send to Vault"), async () => {
    await visit("/openvpn", ".profiles-header");
    await lastVisibleKebab();
    await openPanel({ trigger: ".data-table-row .kebab-btn" });
    await app.click(`${PANEL} [role="menuitem"]`, await indexOfText(`${PANEL} [role="menuitem"]`, "Send to Vault"));
    await app.waitFor(DIALOG);
    const { side } = await openPanel({ trigger: `${DIALOG} .vault-picker-row button`, anchor: `${DIALOG} .vault-picker-row` });
    await escapeCloses(DIALOG);
    await app.press("Escape");
    await app.waitFor(DIALOG, "gone", 2000);
    return `opened ${side}`;
  });

  await check(t("OpenVPN: VPN client picker in Add Profile"), async () => {
    await visit("/openvpn", ".profiles-header");
    await app.click(".profiles-actions button", await indexOfText(".profiles-actions button", "+ Add"));
    await app.waitFor(DIALOG);
    const { side } = await openPanel({ trigger: ".vpn-picker-trigger" });
    await escapeCloses(DIALOG);
    await app.press("Escape");
    await app.waitFor(DIALOG, "gone", 2000);
    return `opened ${side}`;
  });

  for (const [field, label, anchorIndex] of [
    ["saved-login", "Show saved vaults", 0],
    ["account", "Show 1Password accounts", 1],
  ]) {
    await check(t(`Connect: ${field} dropdown`), async () => {
      await visit("/", ".connect-form");
      const trigger = `[aria-label="${label}"]`;
      await app.waitFor(trigger, "visible", 15000).catch(() => skip(`no ${field} choices to offer`));
      await dismissAll();
      const { side } = await openPanel({ trigger, anchor: ".input-with-dropdown", anchorIndex });
      await escapeCloses();
      return `opened ${side}`;
    });
  }
}

const [viewport] = await app.query("body");
const CA_LOAD_MS = 30000;
let status = await app.call("app_status");
for (const started = Date.now(); !status.ca_loaded && Date.now() - started < CA_LOAD_MS; ) {
  await new Promise((resolve) => setTimeout(resolve, 500));
  status = await app.call("app_status");
}
if (!status.ca_loaded) {
  console.error("CA not loaded — connect the dev app to a vault first");
  process.exit(2);
}
await app.resize(SHORT.width, SHORT.height);
let [shrunk] = await app.query("body");
for (let tries = 0; shrunk.rect.height === viewport.rect.height && tries < 20; tries++) {
  await new Promise((resolve) => setTimeout(resolve, 100));
  [shrunk] = await app.query("body");
}
const chrome = { width: SHORT.width - shrunk.rect.width, height: SHORT.height - shrunk.rect.height };
try {
  for (const theme of ["light", "dark"]) await walk(theme);
} finally {
  await dismissAll().catch(() => {});
  await app.navigate("/dashboard").catch(() => {});
  await app.resize(viewport.rect.width + chrome.width, viewport.rect.height + chrome.height).catch(() => {});
}

console.log(`Vault ${status.vault}\n`);
for (const { status, name, detail } of results) console.log(`${status.padEnd(4)}  ${name}${detail ? ` — ${detail}` : ""}`);
const count = (s) => results.filter((r) => r.status === s).length;
console.log(`\n${count("PASS")} passed, ${count("FAIL")} failed, ${count("SKIP")} skipped`);
process.exit(count("FAIL") > 0 ? 1 : 0);
