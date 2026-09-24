import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@solidjs/testing-library";
import { invoke } from "@tauri-apps/api/core";
import Connect from "../pages/Connect";

const createVault = vi.hoisted(() => vi.fn());
const navigate = vi.hoisted(() => vi.fn());
vi.mock("../api/vaults", async (actual) => ({ ...(await actual<object>()), createVault }));
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
});
