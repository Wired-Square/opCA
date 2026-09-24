import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@solidjs/testing-library";
import { invoke } from "@tauri-apps/api/core";
import Connect from "../pages/Connect";

const createVault = vi.hoisted(() => vi.fn());
const listVaults = vi.hoisted(() => vi.fn());
const navigate = vi.hoisted(() => vi.fn());
vi.mock("../api/vaults", async (actual) => ({ ...(await actual<object>()), createVault, listVaults }));
vi.mock("../api/accounts", async (actual) => ({
  ...(await actual<object>()),
  listAccounts: vi.fn(async () => []),
}));
vi.mock("../stores/update", () => ({ availableUpdate: () => null, fetchUpdate: vi.fn() }));
vi.mock("@tauri-apps/plugin-shell", () => ({ open: vi.fn() }));
vi.mock("@solidjs/router", () => ({ useNavigate: () => navigate }));

const mockInvoke = vi.mocked(invoke);

function createVaultNamed(name: string) {
  render(() => <Connect />);
  fireEvent.click(screen.getByRole("button", { name: "New CA in a new vault…" }));
  fireEvent.input(screen.getByLabelText("New 1Password Vault"), { target: { value: name } });
  fireEvent.click(screen.getByRole("button", { name: "Create vault" }));
}

describe("Connect create mode", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockInvoke.mockImplementation(async (cmd) =>
      cmd === "connect"
        ? { connected: true, vault: "New CA", account: null, vault_state: "empty_vault" }
        : undefined,
    );
  });

  it("creates the vault, connects to it and opens the CA page", async () => {
    createVault.mockResolvedValue({ id: "v1", name: "New CA" });
    createVaultNamed("New CA");
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/ca"));
    expect(createVault).toHaveBeenCalledWith("New CA", null);
    expect(mockInvoke).toHaveBeenCalledWith("connect", { vault: "New CA", account: null });
  });

  it("shows the refusal and does not connect when the vault exists", async () => {
    createVault.mockRejectedValue(new Error("Vault already exists: New CA"));
    createVaultNamed("New CA");
    expect(await screen.findByRole("alert")).toHaveTextContent("Vault already exists: New CA");
    expect(mockInvoke).not.toHaveBeenCalledWith("connect", expect.anything());
    expect(navigate).not.toHaveBeenCalled();
  });

  it("switches to the created vault when connecting fails, so a retry connects", async () => {
    createVault.mockResolvedValue({ id: "v1", name: "New CA" });
    let connects = 0;
    mockInvoke.mockImplementation(async (cmd) => {
      if (cmd !== "connect") return undefined;
      if (connects++ === 0) throw new Error("Not signed in");
      return { connected: true, vault: "New CA", account: null, vault_state: "empty_vault" };
    });
    createVaultNamed("New CA");

    expect(await screen.findByRole("alert")).toHaveTextContent(
      'Created vault "New CA" but couldn\'t connect: Not signed in. Connect to try again.',
    );
    expect(screen.getByLabelText("1Password Vault")).toHaveValue("New CA");

    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/dashboard"));
    expect(createVault).toHaveBeenCalledTimes(1);
  });
});

describe("Connect vault list", () => {
  const toggleVaults = () => fireEvent.click(screen.getByRole("button", { name: "Show vaults" }));
  const typeAccount = (value: string) =>
    fireEvent.input(screen.getByLabelText("Account (optional)"), { target: { value } });

  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    listVaults.mockResolvedValue([{ id: "1", name: "Clients" }, { id: "2", name: "Servers" }]);
    mockInvoke.mockImplementation(async (cmd) =>
      cmd === "connect"
        ? { connected: true, vault: "Typed", account: null, vault_state: "valid_ca" }
        : undefined,
    );
    render(() => <Connect />);
  });

  it("lists the account's vaults and fills the field from a pick", async () => {
    typeAccount("acme.1password.com");
    toggleVaults();
    fireEvent.click(await screen.findByRole("option", { name: "Servers" }));
    expect(screen.getByLabelText("1Password Vault")).toHaveValue("Servers");
    expect(listVaults).toHaveBeenCalledWith("acme.1password.com");
  });

  it("lists each account once, and not while typing", async () => {
    toggleVaults();
    await screen.findByRole("option", { name: "Clients" });
    toggleVaults();
    typeAccount("a");
    typeAccount("acme");
    toggleVaults();
    await screen.findByRole("option", { name: "Clients" });
    toggleVaults();
    typeAccount("");
    toggleVaults();
    await screen.findByRole("option", { name: "Clients" });
    expect(listVaults.mock.calls).toEqual([[null], ["acme"]]);
  });

  it("shows a failed listing and retries it on the next open", async () => {
    listVaults.mockRejectedValueOnce(new Error("not signed in"));
    toggleVaults();
    expect(await screen.findByText("not signed in")).toBeInTheDocument();
    toggleVaults();
    toggleVaults();
    await screen.findByRole("option", { name: "Clients" });
    expect(listVaults).toHaveBeenCalledTimes(2);
  });

  it("still connects to a typed vault name without listing", async () => {
    fireEvent.input(screen.getByLabelText("1Password Vault"), { target: { value: "Typed" } });
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/dashboard"));
    expect(mockInvoke).toHaveBeenCalledWith("connect", { vault: "Typed", account: null });
    expect(listVaults).not.toHaveBeenCalled();
  });
});
