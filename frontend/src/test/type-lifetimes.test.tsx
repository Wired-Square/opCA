import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@solidjs/testing-library";
import CA from "../pages/CA";
import { setAppState } from "../stores/app";
import { defaultCertDays, type CaConfig } from "../api/types";

const getCaConfig = vi.hoisted(() => vi.fn());
const updateCaConfig = vi.hoisted(() => vi.fn(async (_config: CaConfig) => {}));
vi.mock("../api/ca", async (actual) => ({
  ...(await actual<object>()),
  getCaInfo: () => new Promise(() => {}),
  getCaConfig,
  updateCaConfig,
}));
vi.mock("@solidjs/router", () => ({ useNavigate: () => vi.fn() }));

describe("defaultCertDays", () => {
  const config = { days: 3650, web_server_days: 90, vpn_server_days: 1000, vpn_client_days: null, device_days: 30 };

  it("takes the type's lifetime, else the CA's days, capping server types at 825", () => {
    expect(defaultCertDays("webserver", config)).toBe(90);
    expect(defaultCertDays("vpnserver", config)).toBe(825);
    expect(defaultCertDays("vpnclient", config)).toBe(3650);
    expect(defaultCertDays("device", config)).toBe(30);
    expect(defaultCertDays("codesigning", config)).toBe(3650);
    expect(defaultCertDays("subordinateca", config)).toBe(90);
  });

  it("leaves the lifetime to the backend when the CA has none", () => {
    expect(defaultCertDays("vpnclient", { days: null })).toBeUndefined();
  });
});

describe("CA Configuration default lifetimes", () => {
  beforeEach(() => {
    setAppState("vaultState", "valid_ca");
    vi.clearAllMocks();
    getCaConfig.mockResolvedValue({ days: 365, web_server_days: 90, vpn_server_days: null, vpn_client_days: null, device_days: 30 });
  });

  async function openConfig() {
    render(() => <CA />);
    fireEvent.click(screen.getByRole("button", { name: "Configuration" }));
    return (await screen.findByLabelText("Web Server Days")) as HTMLInputElement;
  }

  it("shows the set lifetimes and leaves the unset ones blank", async () => {
    expect((await openConfig()).value).toBe("90");
    expect((screen.getByLabelText("Device Days") as HTMLInputElement).value).toBe("30");
    expect((screen.getByLabelText("VPN Server Days") as HTMLInputElement).value).toBe("");
  });

  it("sends a blanked lifetime as 0 so it clears", async () => {
    fireEvent.input(await openConfig(), { target: { value: "" } });
    fireEvent.click(screen.getByRole("button", { name: "Save Configuration" }));

    await waitFor(() => expect(updateCaConfig).toHaveBeenCalled());
    expect(updateCaConfig.mock.calls[0][0]).toMatchObject({ web_server_days: 0, device_days: 30 });
  });

  it("flags a server lifetime over Apple's limit but not a client one", async () => {
    fireEvent.input(await openConfig(), { target: { value: "900" } });
    fireEvent.input(screen.getByLabelText("VPN Client Days"), { target: { value: "900" } });
    expect(screen.getAllByRole("status")).toHaveLength(1);
    expect(screen.getByRole("status")).toHaveTextContent("capped at 825 days");
  });
});
