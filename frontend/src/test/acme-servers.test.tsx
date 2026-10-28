import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, within } from "@solidjs/testing-library";
import { DateModes } from "@wired-square/kit";
import AcmeServers from "../pages/AcmeServers";
import Dashboard from "../pages/Dashboard";
import { setAppState } from "../stores/app";
import type { BrokerRow, DashboardData } from "../api/types";

const listBrokers = vi.hoisted(() => vi.fn());
const renewBroker = vi.hoisted(() => vi.fn());
const renewAllBrokers = vi.hoisted(() => vi.fn());
const revokeBroker = vi.hoisted(() => vi.fn());
const getDashboard = vi.hoisted(() => vi.fn());
const navigate = vi.hoisted(() => vi.fn());
vi.mock("../api/brokers", async (actual) => ({
  ...(await actual<object>()),
  listBrokers,
  renewBroker,
  renewAllBrokers,
  revokeBroker,
}));
vi.mock("../api/dashboard", () => ({ getDashboard }));
vi.mock("@solidjs/router", () => ({ useNavigate: () => navigate }));

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

const rowOf = async (name: string) => (await screen.findByText(name)).closest("tr") as HTMLElement;

describe("ACME servers page", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listBrokers.mockResolvedValue([row(), pending]);
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
      ["Revoke", false],
    ]);
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

describe("dashboard ACME servers tile", () => {
  const dashboard = (brokers: number, brokers_flagged: BrokerRow[]): DashboardData => ({
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

  it("is hidden with no brokers", async () => {
    getDashboard.mockResolvedValue(dashboard(0, []));
    render(() => <Dashboard />);

    await screen.findByText("CA Status");
    expect(screen.queryByText("ACME Servers")).toBeNull();
  });
});
