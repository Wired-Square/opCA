// Phase 15 GUI flow: a new CA in a throwaway vault, then issue → revoke → delete one certificate,
// all through the UI. Teardown forgets the saved login and deletes only the vault this run created.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { connect } from "./mcp.mjs";

const ACCOUNT = "wiredsquare.1password.com";
const STAMP = new Date().toISOString().replace(/\D/g, "").slice(0, 14);
const VAULT = `opca-flow-${STAMP}`;
const CN = `flow-${STAMP}.example.test`;
const CA_SUBJECT = {
  "Common Name": `opCA flow ${STAMP}`,
  Organisation: "Wired Square",
  "Organisational Unit": "opCA flow",
  Email: "flow@example.test",
  City: "Melbourne",
  State: "Victoria",
  Country: "AU",
};
const UI_MS = 15000;
const OP_MS = 180000;
const DIALOG = '[role="dialog"]';
const MENU_ITEM = '.popover [role="menuitem"]';
const SAVED_LOGIN = ".popover .dropdown-item:has(.saved-forget)";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const assert = (ok, message) => {
  if (!ok) throw new Error(message);
};

const execOp = promisify(execFile);
async function op(...args) {
  for (let attempt = 1; ; attempt++) {
    try {
      return (await execOp("op", [...args, "--account", ACCOUNT], { timeout: 120000 })).stdout;
    } catch (e) {
      if (attempt === 1 && /authorization timeout/i.test(`${e.stderr} ${e.message}`)) continue;
      throw e;
    }
  }
}

const app = await connect();
const matches = async (selector, text) => (await app.call("query", { selector, text })).matches;

// Polls until `done()` holds, failing fast on an error the UI shows.
async function settle(what, done, ms = OP_MS) {
  for (const deadline = Date.now() + ms; Date.now() < deadline; await sleep(500)) {
    const [error] = await matches(".page-error, .connect-error");
    if (error) throw new Error(`${what}: ${error.text}`);
    if (await done()) return;
  }
  throw new Error(`${what}: not done after ${ms} ms`);
}

async function onlyIndex(selector, matching, what) {
  const hits = (await matches(selector)).flatMap((m, i) => (matching(m) ? [i] : []));
  assert(hits.length === 1, `${hits.length} ${what}`);
  return hits[0];
}

async function openVaultPicker() {
  await app.navigate("/");
  await app.waitFor(".connect-form", "visible", UI_MS);
  // Lists only this account's vaults, so no other account is asked to unlock.
  await app.type("#account", ACCOUNT);
  await app.click('[aria-label="Show vaults"]');
  await app.waitFor(".popover", "visible", UI_MS);
}

async function closePopover() {
  await app.press("Escape");
  await app.waitFor(".popover", "gone", UI_MS);
}

async function savedLogins() {
  await openVaultPicker();
  const rows = (await matches(SAVED_LOGIN)).map((m) => m.text);
  await closePopover();
  return rows;
}

async function forgetFlowLogin() {
  await openVaultPicker();
  const rows = await matches(`${SAVED_LOGIN} .dropdown-item-primary`);
  const index = rows.findIndex((m) => m.text === VAULT);
  if (index >= 0) await app.click(`${SAVED_LOGIN} .saved-forget`, index);
  await closePopover();
}

async function pickAccount() {
  await app.type("#account", "");
  await app.waitFor('[aria-label="Show 1Password accounts"]', "visible", UI_MS);
  await app.click('[aria-label="Show 1Password accounts"]');
  await app.waitFor(".popover .dropdown-item", "visible", UI_MS);
  const rows = await matches(".popover .dropdown-item");
  assert((await matches(".popover .dropdown-item-secondary")).length === rows.length, "an account row has no address");
  await app.click(".popover .dropdown-item", await onlyIndex(".popover .dropdown-item-secondary", (m) => m.text === ACCOUNT, `account rows read ${ACCOUNT}`));
  const [field] = await matches("#account");
  assert(field.value === ACCOUNT, `account field reads "${field.value}"`);
}

async function createCaInNewVault() {
  await app.navigate("/");
  await app.waitFor(".connect-form", "visible", UI_MS);
  await app.click(".connect-mode-switch");
  await app.call("wait_for", { selector: ".connect-btn", text: "Create vault", state: "visible", timeout_ms: UI_MS });
  await pickAccount();
  await app.type("#vault", VAULT);
  await app.click(".connect-btn");
  await settle("create vault", async () => (await matches(".page-ca .config-form")).length > 0);

  // Every subject field is filled: a blank one is stored as "" and then breaks issuing.
  for (const [label, value] of Object.entries(CA_SUBJECT)) {
    const field = ".page-ca .form-grid > .form-group";
    const index = await onlyIndex(`${field} .form-label`, (m) => m.text === label, `CA fields labelled ${label}`);
    await app.type(`${field}:nth-child(${index + 1}) input`, value);
  }
  await app.call("click", { selector: ".page-ca .form-actions .btn-primary", text: "Initialise CA" });
  await settle("initialise CA", async () => (await matches(".page-ca .tab-btn", "Certificate")).length > 0);

  const status = await app.call("app_status");
  assert(status.vault === VAULT && status.account === ACCOUNT && status.ca_loaded, `app_status ${JSON.stringify(status)}`);
}

// Certs reads ?filter= only on mount, so leave the page first.
async function openAllCerts() {
  await app.navigate("/log");
  await app.waitFor(".page-certs", "gone", UI_MS);
  await app.navigate("/certs?filter=all");
  await app.waitFor(".page-certs", "visible", UI_MS);
  await app.waitFor(".content .spinner", "gone", OP_MS);
}

const flowRows = () => matches(".data-table-row", CN);

async function flowCert() {
  const { certs } = await app.call("list_certs");
  return certs.find((c) => c.cn === CN);
}

async function issue() {
  await app.navigate("/certs/create");
  await app.waitFor("#cert-cn", "visible", UI_MS);
  await app.type("#cert-cn", CN);
  await app.click('.create-form button[type="submit"]');
  await settle("issue", async () => (await matches(".page-certs")).length > 0);
  await openAllCerts();
  await settle("issued row", async () => (await flowRows()).length === 1, UI_MS);
  const [row] = await flowRows();
  assert(row.text.includes("Valid"), `issued row reads "${row.text}"`);
  const cert = await flowCert();
  assert(cert?.status === "Valid", `list_certs has ${JSON.stringify(cert)}`);
  return cert.serial;
}

async function rowAction(label) {
  const index = await onlyIndex(".data-table-row", (m) => m.text.includes(CN), `rows for ${CN}`);
  await app.click(".data-table-row .kebab-btn", index);
  await app.waitFor(MENU_ITEM, "visible", UI_MS);
  await app.click(MENU_ITEM, await onlyIndex(MENU_ITEM, (m) => m.text === label, `${label} menu items`));
  await app.waitFor(DIALOG, "visible", UI_MS);
  await app.click(`${DIALOG} .btn-danger`);
  await settle(label, async () => (await matches(DIALOG)).length === 0);
}

async function revoke() {
  await rowAction("Revoke");
  await settle("revoked row", async () => (await flowRows())[0]?.text.includes("Revoked"), UI_MS);
  const cert = await flowCert();
  assert(cert?.status === "Revoked", `list_certs has ${JSON.stringify(cert)}`);
}

async function remove(serial) {
  await rowAction("Delete");
  await settle("deleted row", async () => (await flowRows()).length === 0, UI_MS);
  const { certs } = await app.call("list_certs");
  assert(!certs.some((c) => c.serial === serial), `list_certs still has serial ${serial}`);
}

async function deleteFlowVault() {
  const vaults = JSON.parse(await op("vault", "list", "--format", "json"));
  const ours = vaults.filter((v) => v.name === VAULT);
  assert(ours.length <= 1, `${ours.length} vaults named ${VAULT}`);
  if (ours.length) await op("vault", "delete", ours[0].id);
  return ours.length === 1;
}

if ((await app.call("app_status")).connected) {
  console.error("Disconnect the dev app first — the flow connects it to a throwaway vault");
  process.exit(2);
}

const results = [];
async function step(name, run) {
  const started = Date.now();
  const outcome = await run().then((detail) => ({ status: "PASS", detail }), (e) => ({ status: "FAIL", detail: e.message }));
  results.push({ name, ...outcome, seconds: (Date.now() - started) / 1000 });
}
const failed = () => results.some((r) => r.status === "FAIL");

console.log(`Vault ${VAULT}, certificate ${CN}\n`);
const savedBefore = await savedLogins();
try {
  let serial;
  await step("new CA in a new vault", createCaInNewVault);
  if (!failed()) await step("issue", async () => `serial ${(serial = await issue())}`);
  if (serial) await step("revoke", revoke);
  if (serial && !failed()) await step("delete", () => remove(serial));
} finally {
  await step("teardown: disconnect", async () => {
    if (!(await app.call("app_status")).connected) return "not connected";
    await app.click('[aria-label="Disconnect"]');
    await app.waitFor(".connect-form", "visible", OP_MS);
  });
  await step("teardown: forget saved login", async () => {
    await forgetFlowLogin();
    const after = await savedLogins();
    assert(JSON.stringify(after) === JSON.stringify(savedBefore), `saved logins were ${JSON.stringify(savedBefore)}, now ${JSON.stringify(after)}`);
  });
  await step("teardown: delete vault", async () => ((await deleteFlowVault()) ? `deleted ${VAULT}` : "never created"));
}

for (const { status, name, detail, seconds } of results) {
  console.log(`${status.padEnd(4)}  ${name} (${seconds.toFixed(1)}s)${detail ? ` — ${detail}` : ""}`);
}
const total = results.reduce((sum, r) => sum + r.seconds, 0);
console.log(`\n${results.filter((r) => r.status === "PASS").length}/${results.length} passed in ${total.toFixed(0)}s`);
process.exit(failed() ? 1 : 0);
