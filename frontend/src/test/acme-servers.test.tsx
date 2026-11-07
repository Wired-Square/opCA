import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, within } from "@solidjs/testing-library";
import { DateModes } from "@wired-square/kit";
import AcmeServer from "../pages/AcmeServer";
import AcmeServers from "../pages/AcmeServers";
import Dashboard from "../pages/Dashboard";
import { setAppState } from "../stores/app";
import { brokersSynced, syncBrokersInBackground } from "../stores/brokerSync";
import type { BrokerCert, BrokerRow, DashboardData, LeafDue } from "../api/types";

const listBrokers = vi.hoisted(() => vi.fn());
const listBrokerCerts = vi.hoisted(() => vi.fn());
const brokerStatus = vi.hoisted(() => vi.fn());
const renewBroker = vi.hoisted(() => vi.fn());
const renewAllBrokers = vi.hoisted(() => vi.fn());
const revokeBroker = vi.hoisted(() => vi.fn());
const revokeBrokerCert = vi.hoisted(() => vi.fn());
const syncBrokers = vi.hoisted(() => vi.fn());
const pauseBroker = vi.hoisted(() => vi.fn());
const getDashboard = vi.hoisted(() => vi.fn());
const navigate = vi.hoisted(() => vi.fn());
vi.mock("../api/brokers", async (actual) => ({
  ...(await actual<object>()),
  listBrokers,
  listBrokerCerts,
  brokerStatus,
  renewBroker,
  renewAllBrokers,
  revokeBroker,
  revokeBrokerCert,
  syncBrokers,
  pauseBroker,
}));
vi.mock("../api/dashboard", () => ({ getDashboard }));
vi.mock("@solidjs/router", () => ({ useNavigate: () => navigate, useParams: () => ({ id: "1" }) }));

const row = (overrides: Partial<BrokerRow> = {}): BrokerRow => ({
  id: 1,
  subordinate_serial: "10",
  url: "https://acme.home.arpa:9443",
  pinned_key: "ab".repeat(32),
  permitted_domains: ["home.arpa"],
  state: "active",
  last_contact: "20261020000000Z",
  created_at: "20261001000000Z",
  updated_at: "20261001000000Z",
  cn: "acme.home.arpa",
  expiry_date: "20270101000000Z",
  issuer_state: "issuing",
  concerns: [],
  ...overrides,
});

const pending = row({
  id: 2,
  cn: "acme.lab.example",
  url: "https://acme.lab.example:9443",
  permitted_domains: ["lab.example"],
  last_contact: null,
  concerns: [{ concern: "not_delivered" }],
});

const cert = (overrides: Partial<BrokerCert> = {}): BrokerCert => ({
  broker_id: 1,
  serial: "111",
  common_name: "nas.home.arpa",
  sans: ["nas.home.arpa", "files.home.arpa"],
  not_before: "20261101000000Z",
  not_after: "20991201000000Z",
  issuer_serial: "10",
  revoked_at: null,
  revocation_reason: null,
  changed: 1,
  ...overrides,
});

const rowOf = async (name: string) => (await screen.findByText(name)).closest("tr") as HTMLElement;

describe("ACME servers page", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listBrokers.mockResolvedValue([row(), pending]);
    listBrokerCerts.mockResolvedValue([]);
  });

  it("lists each broker with its domains, state and a marker for one not delivered", async () => {
    render(() => <AcmeServers />);

    const healthy = await rowOf("acme.home.arpa");
    expect(healthy).toHaveTextContent("home.arpa");
    expect(within(healthy).getByText("active")).toHaveClass("status-badge", "status-active");
    expect(healthy).not.toHaveTextContent("not delivered");
    expect(within(await rowOf("acme.lab.example")).getByText("not delivered")).toHaveClass("status-badge");
  });

  it("shows the broker's URL under its name and dates in the shared UTC/local mode", async () => {
    render(() => (
      <DateModes initial="utc" locale="en-AU">
        <AcmeServers />
      </DateModes>
    ));

    const healthy = await rowOf("acme.home.arpa");
    expect(within(healthy).getByText("https://acme.home.arpa:9443")).toHaveClass("broker-url");
    expect(within(healthy).getByText("1 Jan 2027, 00:00:00 UTC")).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /Subordinate Expires/ })).toContainElement(
      screen.getByRole("button", { name: "UTC" }),
    );
  });

  it("counts each broker's issued certificates and opens its page from the row, not the ⋮", async () => {
    listBrokerCerts.mockResolvedValue([cert(), cert({ serial: "222", revoked_at: "20261102000000Z" })]);
    render(() => <AcmeServers />);

    const healthy = await rowOf("acme.home.arpa");
    expect(await within(healthy).findByText("2 issued, 1 revoked")).toBeInTheDocument();
    expect(await rowOf("acme.lab.example")).not.toHaveTextContent("issued");

    fireEvent.click(within(healthy).getByRole("button", { name: "Actions for acme.home.arpa" }));
    expect(navigate).not.toHaveBeenCalled();
    fireEvent.click(healthy);
    expect(navigate).toHaveBeenCalledWith("/acme/1");
  });

  it("reports the issued counts with the status and refreshes the list it synced", async () => {
    brokerStatus.mockResolvedValue({
      state: "issuing",
      subordinate_serial: "10",
      subordinate_not_after: "2027-01-01T00:00:00Z",
      config: { permitted_domains: ["home.arpa"], leaf_days: 30, leaf_max_days: 45, challenges: [] },
      versions: { api: 1, broker: "0.103.0" },
      issued: { total: 4, revoked: 1 },
    });
    render(() => <AcmeServers />);
    const healthy = await rowOf("acme.home.arpa");
    expect(listBrokerCerts).toHaveBeenCalledTimes(1);

    fireEvent.click(within(healthy).getByRole("button", { name: "Actions for acme.home.arpa" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Status" }));

    expect(
      await screen.findByText("acme.home.arpa: issuing, serial 10, broker 0.103.0, 4 issued, 1 revoked"),
    ).toBeInTheDocument();
    expect(listBrokerCerts).toHaveBeenCalledTimes(2);
  });

  it("dims a revoked broker and offers its actions from the row menu", async () => {
    listBrokers.mockResolvedValue([row({ state: "revoked" }), pending]);
    render(() => <AcmeServers />);

    const revoked = await rowOf("acme.home.arpa");
    expect(revoked).toHaveClass("data-table-row-ignored");
    fireEvent.click(within(revoked).getByRole("button", { name: "Actions for acme.home.arpa" }));
    const items = screen.getAllByRole("menuitem");
    expect(items.map((i) => [i.textContent, i.getAttribute("aria-disabled") === "true"])).toEqual([
      ["Status", false],
      ["Renew", true],
      ["Pause", true],
      ["Revoke", false],
    ]);
  });

  it("pauses a broker from its menu, and offers to resume one recorded paused", async () => {
    const status = (state: string) => ({
      state,
      subordinate_serial: "10",
      subordinate_not_after: "2027-01-01T00:00:00Z",
      config: { permitted_domains: ["home.arpa"], leaf_days: 30, leaf_max_days: 45, challenges: [] },
      versions: { api: 1, broker: "0.103.0" },
      issued: null,
    });
    pauseBroker.mockResolvedValue(status("paused"));
    listBrokers.mockResolvedValueOnce([row()]);
    listBrokers.mockResolvedValue([row({ issuer_state: "paused", concerns: [{ concern: "paused" }] })]);
    render(() => <AcmeServers />);

    fireEvent.click(within(await rowOf("acme.home.arpa")).getByRole("button", { name: "Actions for acme.home.arpa" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Pause" }));

    expect(await screen.findByText("acme.home.arpa: paused, serial 10, broker 0.103.0")).toBeInTheDocument();
    expect(pauseBroker).toHaveBeenCalledWith(1, true);
    const paused = within(await rowOf("acme.home.arpa"));
    expect(await paused.findByText("issuance paused")).toHaveClass("status-badge", "status-paused");
    fireEvent.click(paused.getByRole("button", { name: "Actions for acme.home.arpa" }));
    pauseBroker.mockResolvedValue(status("issuing"));
    fireEvent.click(screen.getByRole("menuitem", { name: "Resume" }));
    await vi.waitFor(() => expect(pauseBroker).toHaveBeenCalledWith(1, false));
  });

  it("renews all and reports each broker, offering to confirm changed domains", async () => {
    renewAllBrokers.mockResolvedValue([
      { id: 1, outcome: "domains_changed", recorded: ["home.arpa"], configured: ["home.arpa", "lab.home.arpa"] },
      { id: 2, outcome: "unreachable", error: { kind: "unreachable", message: "connection refused" } },
    ]);
    renewBroker.mockResolvedValue({ outcome: "renewed", serial: "11", status: {} });
    render(() => <AcmeServers />);
    await rowOf("acme.home.arpa");

    screen.getByRole("button", { name: "Renew All" }).click();

    const outcomes = within(await screen.findByLabelText("Renewal outcomes"));
    expect(await outcomes.findByText(/Now asks for home.arpa, lab.home.arpa/)).toBeInTheDocument();
    expect(outcomes.getByText("Unreachable: connection refused")).toBeInTheDocument();
    outcomes.getByRole("button", { name: "Confirm and Renew" }).click();

    await vi.waitFor(() => expect(renewBroker).toHaveBeenCalledWith(1, true));
    expect(await outcomes.findByText("Renewed (serial 11)")).toBeInTheDocument();
  });

  it("revokes through the destructive confirm and says when the broker was not told", async () => {
    revokeBroker.mockResolvedValue({
      broker: { ...row(), state: "revoked" },
      notice: "not_told",
      error: { kind: "unreachable", message: "timed out" },
    });
    render(() => <AcmeServers />);
    const healthy = await rowOf("acme.home.arpa");

    fireEvent.click(within(healthy).getByRole("button", { name: "Actions for acme.home.arpa" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Revoke" }));
    expect(screen.getByText(/This cannot be undone/)).toBeInTheDocument();
    screen.getByRole("button", { name: "Revoke" }).click();

    await vi.waitFor(() => expect(revokeBroker).toHaveBeenCalledWith(1));
    expect(await screen.findByText(/the broker was not told: timed out/)).toBeInTheDocument();
  });
});

describe("an ACME server's page", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listBrokers.mockResolvedValue([row(), pending]);
    listBrokerCerts.mockResolvedValue([cert()]);
  });

  const openIssued = async () => {
    render(() => <AcmeServer />);
    return within(await screen.findByRole("table", { name: "Certificates issued by acme.home.arpa" }));
  };

  it("heads the page with the broker, its summary and Back to list", async () => {
    listBrokerCerts.mockResolvedValue([cert(), cert({ serial: "9", broker_id: 2, common_name: "lab.lab.example" })]);
    render(() => (
      <DateModes initial="utc" locale="en-AU">
        <AcmeServer />
      </DateModes>
    ));

    expect(await screen.findByRole("heading", { name: "acme.home.arpa" })).toBeInTheDocument();
    const grid = within(document.querySelector(".detail-grid") as HTMLElement);
    const summary = (label: string) => grid.getByText(label).closest(".detail-row") as HTMLElement;
    expect(summary("URL")).toHaveTextContent("https://acme.home.arpa:9443");
    expect(summary("Domains")).toHaveTextContent("home.arpa");
    expect(within(summary("State")).getByText("active")).toHaveClass("status-badge");
    expect(summary("Subordinate Expires")).toHaveTextContent("1 Jan 2027, 00:00:00 UTC");
    expect(summary("Last Contact")).toHaveTextContent("20 Oct 2026, 00:00:00 UTC");
    expect(summary("Issued")).toHaveTextContent("1 issued");
    expect(await screen.findByText("nas.home.arpa")).toBeInTheDocument();
    expect(screen.queryByText("lab.lab.example")).toBeNull();

    screen.getByRole("button", { name: "Back to list" }).click();
    expect(navigate).toHaveBeenCalledWith("/acme");
  });

  it("offers the broker's actions from its header", async () => {
    render(() => <AcmeServer />);

    fireEvent.click(await screen.findByRole("button", { name: "Actions for acme.home.arpa" }));
    for (const name of ["Status", "Renew", "Revoke"]) expect(screen.getByRole("menuitem", { name })).toBeInTheDocument();
  });

  it("lists every issued certificate with its names and state", async () => {
    listBrokerCerts.mockResolvedValue([
      cert(),
      cert({ serial: "222", common_name: null, sans: ["printer.home.arpa"], revoked_at: "20261102000000Z", changed: 3 }),
      cert({ serial: "333", common_name: "old.home.arpa", sans: ["old.home.arpa"], not_after: "20200101000000Z" }),
    ]);
    const issued = await openIssued();

    const state = (name: string) => within(issued.getByText(name).closest("tr") as HTMLElement);
    expect(state("nas.home.arpa").getByText("files.home.arpa")).toHaveClass("broker-sans");
    expect(state("nas.home.arpa").getByText("valid")).toHaveClass("status-valid");
    expect(state("printer.home.arpa").getByText("revoked")).toHaveClass("status-revoked");
    expect(state("old.home.arpa").getByText("expired")).toHaveClass("status-expired");
  });

  it("revokes an issued certificate from its right-click menu with the reason picked", async () => {
    listBrokerCerts.mockResolvedValueOnce([cert()]);
    listBrokerCerts.mockResolvedValue([cert({ revoked_at: "20261107000000Z", revocation_reason: 1, changed: 2 })]);
    revokeBrokerCert.mockResolvedValue(cert({ revoked_at: "20261107000000Z", revocation_reason: 1, changed: 2 }));
    const issued = await openIssued();

    fireEvent.contextMenu(issued.getByText("nas.home.arpa").closest("tr") as HTMLElement);
    fireEvent.click(screen.getByRole("menuitem", { name: "Revoke…" }));
    const reason = screen.getByLabelText("Reason") as HTMLSelectElement;
    expect([...reason.options].map((o) => o.textContent)).toContain("cessation of operation");
    fireEvent.change(reason, { target: { value: "1" } });
    screen.getByRole("button", { name: "Revoke" }).click();

    await vi.waitFor(() => expect(revokeBrokerCert).toHaveBeenCalledWith(1, "111", 1));
    expect(await screen.findByText(/revoked nas.home.arpa/)).toBeInTheDocument();
    const shown = within((await screen.findByText("nas.home.arpa")).closest("tr") as HTMLElement);
    expect(await shown.findByText("revoked")).toHaveClass("status-revoked");
  });

  it("keeps the dialog open on the broker's refusal and offers nothing for a revoked or expired certificate", async () => {
    listBrokerCerts.mockResolvedValue([
      cert(),
      cert({ serial: "222", common_name: "gone.home.arpa", revoked_at: "20261102000000Z" }),
      cert({ serial: "333", common_name: "old.home.arpa", not_after: "20200101000000Z" }),
    ]);
    revokeBrokerCert.mockRejectedValue("unreachable: connection refused");
    const issued = await openIssued();

    for (const name of ["gone.home.arpa", "old.home.arpa"]) {
      fireEvent.click(issued.getByRole("button", { name: `Actions for ${name}` }));
      const menu = within(screen.getByRole("menu", { name: `Actions for ${name}` }));
      expect(menu.getByRole("menuitem", { name: "Revoke…" })).toHaveAttribute("aria-disabled", "true");
    }
    fireEvent.click(issued.getByRole("button", { name: "Actions for nas.home.arpa" }));
    const menu = within(screen.getByRole("menu", { name: "Actions for nas.home.arpa" }));
    fireEvent.click(menu.getByRole("menuitem", { name: "Revoke…" }));
    screen.getByRole("button", { name: "Revoke" }).click();

    expect(await screen.findByText(/connection refused/)).toBeInTheDocument();
    expect(revokeBrokerCert).toHaveBeenCalledWith(1, "111", 0);
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });
});

describe("dashboard ACME servers tile", () => {
  const dashboard = (brokers: number, brokers_flagged: BrokerRow[], leaves_due: LeafDue[] = []): DashboardData => ({
    ca_valid: true,
    ca_cn: "Test CA",
    ca_expiry: null,
    ca_expiry_warning: null,
    crl_present: true,
    crl_next_update: null,
    crl_expiry_warning: null,
    total_certs: 0,
    valid_certs: 0,
    expired_certs: 0,
    expiring_certs: 0,
    warning_certs: 0,
    revoked_certs: 0,
    pending_csrs: 0,
    has_public_store: false,
    crl_batch_enabled: false,
    crl_batch: null,
    brokers,
    brokers_flagged,
    leaves_due,
    action_items: [],
  });

  const tile = async () => (await screen.findByText("ACME Servers")).closest(".stat-card") as HTMLElement;

  beforeEach(() => {
    vi.clearAllMocks();
    setAppState("vaultState", "valid_ca");
  });

  it("names each flagged broker and why, and opens the page", async () => {
    getDashboard.mockResolvedValue(
      dashboard(3, [
        row({ concerns: [{ concern: "expiring", days: 12 }, { concern: "silent", days: 40 }] }),
        pending,
      ]),
    );
    render(() => <Dashboard />);

    const card = await tile();
    expect(card).toHaveTextContent("2 of 3 need attention");
    expect(card).toHaveTextContent("acme.home.arpa: expires in 12 days, not heard from in 40 days");
    expect(card).toHaveTextContent("acme.lab.example: signed, not delivered");
    card.click();
    expect(navigate).toHaveBeenCalledWith("/acme");
  });

  it("refreshes, as the ACME Servers page does, when a background sync lands, and not when it is skipped", async () => {
    getDashboard.mockResolvedValue(dashboard(1, []));
    listBrokers.mockResolvedValue([row()]);
    listBrokerCerts.mockResolvedValue([]);
    render(() => (
      <>
        <Dashboard />
        <AcmeServers />
      </>
    ));
    await tile();
    const synced = brokersSynced();
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    syncBrokers.mockRejectedValueOnce(new Error("the lock is held"));
    syncBrokersInBackground();
    await vi.waitFor(() => expect(warn).toHaveBeenCalled());
    expect(brokersSynced()).toBe(synced);
    syncBrokers.mockResolvedValueOnce(undefined);
    syncBrokersInBackground();

    await vi.waitFor(() => expect(getDashboard).toHaveBeenCalledTimes(2));
    expect(listBrokers).toHaveBeenCalledTimes(2);
    warn.mockRestore();
  });

  it("lists each certificate due for renewal, opening its broker's page", async () => {
    getDashboard.mockResolvedValue(
      dashboard(1, [], [
        { broker_id: 1, broker: "acme.home.arpa", serial: "111", name: "nas.home.arpa", days: 12 },
        { broker_id: 1, broker: "acme.home.arpa", serial: "112", name: "old.home.arpa", days: -3 },
      ]),
    );
    render(() => <Dashboard />);

    const card = await tile();
    expect(card).toHaveTextContent("1 healthy");
    expect(within(card).getByText("1 healthy")).toHaveClass("text-warning");
    expect(card).toHaveTextContent("2 certificates need renewing");
    const due = within(within(card).getByRole("list", { name: "Certificates to renew" }));
    expect(due.getByRole("button", { name: "old.home.arpa on acme.home.arpa: expired 3 days ago" })).toBeInTheDocument();
    due.getByRole("button", { name: "nas.home.arpa on acme.home.arpa: expires in 12 days" }).click();
    expect(navigate).toHaveBeenCalledWith("/acme/1");
    expect(navigate).not.toHaveBeenCalledWith("/acme");
  });

  it("is hidden with no brokers", async () => {
    getDashboard.mockResolvedValue(dashboard(0, []));
    render(() => <Dashboard />);

    await screen.findByText("CA Status");
    expect(screen.queryByText("ACME Servers")).toBeNull();
  });
});
