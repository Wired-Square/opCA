import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@solidjs/testing-library";
import Dashboard from "../pages/Dashboard";
import CRL from "../pages/CRL";
import CA from "../pages/CA";
import { setAppState } from "../stores/app";
import type { CaConfig, CrlBatch, CrlInfo, DashboardData } from "../api/types";

const getDashboard = vi.hoisted(() => vi.fn());
const getCrlInfo = vi.hoisted(() => vi.fn());
const generateCrl = vi.hoisted(() => vi.fn());
const getCaConfig = vi.hoisted(() => vi.fn());
const updateCaConfig = vi.hoisted(() => vi.fn(async (_config: CaConfig) => {}));
vi.mock("../api/dashboard", () => ({ getDashboard }));
vi.mock("../api/crl", async (actual) => ({
  ...(await actual<object>()),
  getCrlInfo,
  backfillCrl: getCrlInfo,
  generateCrl,
}));
vi.mock("../api/ca", async (actual) => ({
  ...(await actual<object>()),
  getCaInfo: () => new Promise(() => {}),
  getCaConfig,
  updateCaConfig,
}));
vi.mock("@solidjs/router", () => ({ useNavigate: () => vi.fn() }));

const batch = (overrides: Partial<CrlBatch> = {}): CrlBatch => ({
  first_number: 6,
  last_number: 10,
  due_number: 7,
  signed_until: "20261102000000Z",
  remaining: 3,
  count: 5,
  low_cover: false,
  ...overrides,
});

const dashboard = (overrides: Partial<DashboardData> = {}): DashboardData => ({
  ca_valid: true,
  ca_cn: "Test CA",
  ca_expiry: null,
  ca_expiry_warning: null,
  crl_present: true,
  crl_next_update: "20261005000000Z",
  crl_expiry_warning: null,
  total_certs: 0,
  valid_certs: 0,
  expired_certs: 0,
  expiring_certs: 0,
  warning_certs: 0,
  revoked_certs: 0,
  pending_csrs: 0,
  has_public_store: false,
  crl_batch_enabled: true,
  crl_batch: batch(),
  action_items: [],
  ...overrides,
});

const crlInfo = (overrides: Partial<CrlInfo> = {}): CrlInfo => ({
  issuer: "CN=Test CA",
  last_update: "20260925000000Z",
  next_update: "20261005000000Z",
  crl_number: 6,
  revoked_count: 0,
  crl_pem: null,
  has_public_store: false,
  has_crl: null,
  crl_batch_enabled: true,
  crl_batch: batch(),
  ...overrides,
});

const config = (overrides: Partial<CaConfig> = {}): CaConfig => ({
  next_serial: 2,
  next_crl_serial: 11,
  org: null,
  ou: null,
  email: null,
  city: null,
  state: null,
  country: null,
  ca_url: null,
  crl_url: null,
  days: 365,
  crl_days: 30,
  ca_public_store: null,
  ca_private_store: null,
  ca_backup_store: null,
  ca_aws_region: null,
  crl_batch_enabled: false,
  ...overrides,
});

const tile = async (label: string) => (await screen.findByText(label)).closest(".stat-card") as HTMLElement;

describe("dashboard CRL batch cover", () => {
  beforeEach(() => {
    setAppState("vaultState", "valid_ca");
    vi.clearAllMocks();
  });

  it("shows what is left to release and when the batch runs out", async () => {
    getDashboard.mockResolvedValue(dashboard());
    render(() => <Dashboard />);

    const card = await tile("CRL Batch");
    expect(card).toHaveTextContent("3 of 5 unreleased");
    expect(card).toHaveTextContent(/signed until.*2 Nov 2026/);
    expect(card.querySelector(".stat-card-warning")).toBeNull();
    expect(await tile("CRL Status")).not.toHaveTextContent("next update");
  });

  it("warns when fewer than two CRLs are left to release", async () => {
    getDashboard.mockResolvedValue(dashboard({ crl_batch: batch({ remaining: 1, low_cover: true }) }));
    render(() => <Dashboard />);

    const card = await tile("CRL Batch");
    expect(card.querySelector(".text-warning")).toHaveTextContent("1 of 5 unreleased");
    expect(card).toHaveTextContent("fewer than 2 left to release");
  });

  it("says a batch is on but not yet signed", async () => {
    getDashboard.mockResolvedValue(dashboard({ crl_batch: null }));
    render(() => <Dashboard />);

    expect(await tile("CRL Batch")).toHaveTextContent("Not signed");
    expect(await tile("CRL Status")).toHaveTextContent("next update");
  });

  it("has no batch tile while batches are off", async () => {
    getDashboard.mockResolvedValue(dashboard({ crl_batch_enabled: false, crl_batch: null }));
    render(() => <Dashboard />);

    expect(await screen.findByText("CRL Status")).toBeInTheDocument();
    expect(screen.queryByText("CRL Batch")).not.toBeInTheDocument();
  });
});

describe("CRL page batch", () => {
  beforeEach(() => vi.clearAllMocks());

  it("shows the batch and that CRL Days does not apply", async () => {
    getCrlInfo.mockResolvedValue(crlInfo());
    render(() => <CRL />);

    const row = (label: string) => screen.getByText(label).closest(".detail-row");
    expect(await screen.findByText("Pre-signed Batch")).toBeInTheDocument();
    expect(row("CRL Numbers")).toHaveTextContent("6–10");
    expect(row("Due CRL")).toHaveTextContent("7");
    expect(row("Signed Until")).toHaveTextContent("2 Nov 2026");
    expect(row("Unreleased")).toHaveTextContent("3 of 5");
    expect(screen.getByText(/CRL Days does not apply/)).toBeInTheDocument();
  });

  it("reports a generate in batch mode as a signed and uploaded batch", async () => {
    getCrlInfo.mockResolvedValue(crlInfo());
    generateCrl.mockResolvedValue(crlInfo({ crl_batch: batch({ first_number: 11, last_number: 15 }) }));
    render(() => <CRL />);

    fireEvent.click(await screen.findByRole("button", { name: "Generate CRL" }));

    expect(await screen.findByText(/CRLs #11–15 signed and uploaded to the private store/)).toBeInTheDocument();
  });

  it("shows no batch while batches are off", async () => {
    getCrlInfo.mockResolvedValue(crlInfo({ crl_batch_enabled: false, crl_batch: null }));
    render(() => <CRL />);

    expect(await screen.findByText("CRL Number")).toBeInTheDocument();
    expect(screen.queryByText("Pre-signed Batch")).not.toBeInTheDocument();
    expect(screen.queryByText(/CRL Days does not apply/)).not.toBeInTheDocument();
  });
});

describe("CA settings CRL batch toggle", () => {
  beforeEach(() => {
    setAppState("vaultState", "valid_ca");
    vi.clearAllMocks();
  });

  async function openStores(c: CaConfig) {
    getCaConfig.mockResolvedValue(c);
    render(() => <CA />);
    fireEvent.click(screen.getByRole("button", { name: "Stores" }));
    return screen.findByRole("checkbox", { name: "Pre-signed CRL batches" });
  }

  it("can't be turned on without a private store", async () => {
    const toggle = await openStores(config());
    expect(toggle).toBeDisabled();
    expect(screen.getByText("CRL batches need a private store.")).toBeInTheDocument();
  });

  it("saves turning batches on and off", async () => {
    const toggle = await openStores(config({ ca_private_store: "rsync://host/ca" }));
    expect(toggle).toBeEnabled();

    getCaConfig.mockResolvedValue(config({ ca_private_store: "rsync://host/ca", crl_batch_enabled: true }));
    fireEvent.click(toggle);
    fireEvent.click(screen.getByRole("button", { name: "Save Stores" }));
    await waitFor(() => expect(updateCaConfig).toHaveBeenCalled());
    expect(updateCaConfig.mock.calls[0][0].crl_batch_enabled).toBe(true);

    fireEvent.click(await screen.findByRole("checkbox", { name: "Pre-signed CRL batches", checked: true }));
    fireEvent.click(await screen.findByRole("button", { name: "Save Stores" }));
    await waitFor(() => expect(updateCaConfig).toHaveBeenCalledTimes(2));
    expect(updateCaConfig.mock.calls[1][0].crl_batch_enabled).toBe(false);
  });

  it("says CRL Days is unused while batches are on", async () => {
    getCaConfig.mockResolvedValue(config({ ca_private_store: "rsync://host/ca", crl_batch_enabled: true }));
    render(() => <CA />);
    fireEvent.click(screen.getByRole("button", { name: "Configuration" }));

    expect(await screen.findByText("Not used while CRL batches are on.")).toBeInTheDocument();
  });
});
