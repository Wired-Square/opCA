import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@solidjs/testing-library";
import Dashboard from "../pages/Dashboard";
import { setAppState } from "../stores/app";
import type { DashboardData } from "../api/types";

const getDashboard = vi.hoisted(() => vi.fn());
const navigate = vi.hoisted(() => vi.fn());
vi.mock("../api/dashboard", () => ({ getDashboard }));
vi.mock("@solidjs/router", () => ({ useNavigate: () => navigate }));

const dashboard: DashboardData = {
  ca_valid: true,
  ca_cn: "Test CA",
  ca_expiry: null,
  ca_expiry_warning: null,
  crl_present: true,
  crl_next_update: null,
  crl_expiry_warning: null,
  total_certs: 2,
  valid_certs: 2,
  expired_certs: 0,
  expiring_certs: 2,
  warning_certs: 2,
  revoked_certs: 0,
  pending_csrs: 0,
  has_public_store: false,
  crl_batch_enabled: false,
  crl_batch: null,
  brokers: 0,
  brokers_flagged: [],
  action_items: [
    {
      id: "expiring_certs",
      severity: "warning",
      message: "2 certificates expire within 30 days",
      button_label: "View",
      action: "view_expiring_certs",
    },
  ],
};

describe("dashboard renewal nudge", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setAppState("vaultState", "valid_ca");
  });

  it("opens the certificates expiring soon", async () => {
    getDashboard.mockResolvedValue(dashboard);
    render(() => <Dashboard />);

    expect(await screen.findByText("2 certificates expire within 30 days")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "View" }));
    expect(navigate).toHaveBeenCalledWith("/certs?filter=expiring");
  });
});
