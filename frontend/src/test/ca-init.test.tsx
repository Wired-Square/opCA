import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@solidjs/testing-library";
import CA from "../pages/CA";
import { setAppState } from "../stores/app";

const initCa = vi.hoisted(() => vi.fn(async (_config: object) => {}));
const getCaInfo = vi.hoisted(() => vi.fn(() => new Promise(() => {})));
const getCaConfig = vi.hoisted(() => vi.fn(() => new Promise(() => {})));
vi.mock("../api/ca", async (actual) => ({
  ...(await actual<object>()),
  initCa,
  getCaInfo,
  getCaConfig,
}));
vi.mock("@solidjs/router", () => ({ useNavigate: () => vi.fn() }));

describe("CA init tab", () => {
  beforeEach(() => {
    setAppState("vaultState", "empty_vault");
    vi.clearAllMocks();
  });

  it("requires a Common Name and sends it with the default lifetimes", async () => {
    render(() => <CA />);
    const [, button] = screen.getAllByRole("button", { name: "Initialise CA" });
    expect(button).toBeDisabled();

    fireEvent.input(screen.getByLabelText("Common Name"), { target: { value: "Example Root CA" } });
    fireEvent.click(button);

    await waitFor(() => expect(initCa).toHaveBeenCalled());
    expect(initCa.mock.calls[0][0]).toMatchObject({
      cn: "Example Root CA",
      next_serial: 1,
      ca_days: 3650,
      days: 365,
      crl_days: 30,
    });
  });

  it("flags a certificate lifetime over Apple's 825-day server limit", () => {
    render(() => <CA />);
    const days = screen.getByLabelText("Certificate Days");
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    fireEvent.input(days, { target: { value: "3650" } });
    expect(screen.getByRole("status")).toHaveTextContent("capped at 825 days");
  });

  it("switches to the new CA's certificate tab without reloading", async () => {
    render(() => <CA />);
    const [, button] = screen.getAllByRole("button", { name: "Initialise CA" });

    fireEvent.input(screen.getByLabelText("Common Name"), { target: { value: "Example Root CA" } });
    fireEvent.click(button);

    expect(await screen.findByRole("button", { name: "Certificate" })).toBeInTheDocument();
    expect(screen.queryByLabelText("Common Name")).not.toBeInTheDocument();
    expect(getCaInfo).toHaveBeenCalled();
  });

  it("shows a failed init without an Error: prefix", async () => {
    initCa.mockRejectedValueOnce(new Error("Vault is locked"));
    render(() => <CA />);
    const [, button] = screen.getAllByRole("button", { name: "Initialise CA" });

    fireEvent.input(screen.getByLabelText("Common Name"), { target: { value: "Example Root CA" } });
    fireEvent.click(button);

    expect(await screen.findByText("Vault is locked")).toBeInTheDocument();
  });

  it("does not retrieve the CA from a vault without one", () => {
    render(() => <CA />);
    expect(getCaInfo).not.toHaveBeenCalled();
    expect(getCaConfig).not.toHaveBeenCalled();
  });
});
