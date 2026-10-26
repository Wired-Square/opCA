import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor, within } from "@solidjs/testing-library";
import { invoke } from "@tauri-apps/api/core";
import Connect from "../pages/Connect";

const createVault = vi.hoisted(() => vi.fn());
const listVaults = vi.hoisted(() => vi.fn());
const listAccounts = vi.hoisted(() => vi.fn());
const navigate = vi.hoisted(() => vi.fn());
vi.mock("../api/vaults", async (actual) => ({ ...(await actual<object>()), createVault, listVaults }));
vi.mock("../api/accounts", async (actual) => ({ ...(await actual<object>()), listAccounts }));
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
    listAccounts.mockResolvedValue([]);
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

const vaultField = () => screen.getByLabelText("1Password Vault");
const accountField = () => screen.getByLabelText("1Password Account (optional)");
const typeAccount = (value: string) => fireEvent.input(accountField(), { target: { value } });
const browseVaults = (account = "the default account") =>
  fireEvent.click(screen.getByRole("button", { name: `Browse vaults in ${account}` }));

function connectsAs(vault: string) {
  mockInvoke.mockImplementation(async (cmd) =>
    cmd === "connect" ? { connected: true, vault, account: null, vault_state: "valid_ca" } : undefined,
  );
}

describe("Connect vault list", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    listAccounts.mockResolvedValue([]);
    listVaults.mockResolvedValue([{ id: "1", name: "Clients" }, { id: "2", name: "Servers" }]);
    connectsAs("Typed");
  });

  it("puts the account field first, autofocused", () => {
    render(() => <Connect />);
    const [first, second] = screen.getAllByRole("textbox");
    expect(first).toBe(accountField());
    expect(second).toBe(vaultField());
    expect(accountField()).toHaveAttribute("autofocus");
    expect(vaultField()).not.toHaveAttribute("autofocus");
  });

  it("never lists vaults on focus or typing in the vault field", async () => {
    localStorage.setItem("opca_saved_logins", JSON.stringify([{ vault: "Clients", account: null }]));
    render(() => <Connect />);
    vaultField().focus();
    fireEvent.focus(vaultField());
    fireEvent.input(vaultField(), { target: { value: "Cli" } });
    typeAccount("acme.1password.com");
    await Promise.resolve();
    expect(listVaults).not.toHaveBeenCalled();
    expect(screen.queryByRole("listbox")).not.toBeInTheDocument();
  });

  it("browses the vaults of the account in the field and fills the field from a pick", async () => {
    render(() => <Connect />);
    typeAccount("acme.1password.com");
    browseVaults("acme.1password.com");
    expect(await screen.findByRole("listbox", { name: "Vaults in acme.1password.com" })).toBeInTheDocument();
    fireEvent.click(await screen.findByRole("option", { name: "Servers" }));
    expect(vaultField()).toHaveValue("Servers");
    expect(listVaults).toHaveBeenCalledWith("acme.1password.com");
  });

  it("browses the default account when the account field is blank", async () => {
    render(() => <Connect />);
    browseVaults();
    expect(await screen.findByRole("listbox", { name: "Vaults in the default account" })).toBeInTheDocument();
    await screen.findByRole("option", { name: "Clients" });
    expect(listVaults).toHaveBeenCalledWith(null);
  });

  it("closes the list on Escape, leaving focus in the field", async () => {
    render(() => <Connect />);
    const field = vaultField();
    field.focus();
    browseVaults();
    await screen.findByRole("option", { name: "Clients" });
    fireEvent.keyDown(field, { key: "Escape" });
    expect(screen.queryByRole("listbox")).not.toBeInTheDocument();
    expect(field).toHaveFocus();
  });

  it("lists each account once", async () => {
    render(() => <Connect />);
    browseVaults();
    await screen.findByRole("option", { name: "Clients" });
    browseVaults();
    typeAccount("a");
    typeAccount("acme");
    browseVaults("acme");
    await screen.findByRole("option", { name: "Clients" });
    browseVaults("acme");
    typeAccount("");
    browseVaults();
    await screen.findByRole("option", { name: "Clients" });
    expect(listVaults.mock.calls).toEqual([[null], ["acme"]]);
  });

  it("never shows one account's vaults while browsing another", async () => {
    render(() => <Connect />);
    browseVaults();
    await screen.findByRole("option", { name: "Clients" });
    typeAccount("acme");
    expect(screen.queryByRole("listbox")).not.toBeInTheDocument();
    listVaults.mockReturnValueOnce(new Promise(() => {}));
    browseVaults("acme");
    expect(await screen.findByText("Loading vaults…")).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "Clients" })).not.toBeInTheDocument();
  });

  it("shows a failed listing and retries it on the next browse", async () => {
    listVaults.mockRejectedValueOnce(new Error("not signed in"));
    render(() => <Connect />);
    browseVaults();
    expect(await screen.findByText("not signed in")).toBeInTheDocument();
    browseVaults();
    browseVaults();
    await screen.findByRole("option", { name: "Clients" });
    expect(listVaults).toHaveBeenCalledTimes(2);
  });

  it("offers no vault browsing when creating a vault", () => {
    render(() => <Connect />);
    fireEvent.click(screen.getByRole("button", { name: "New CA in a new vault…" }));
    expect(screen.queryByRole("button", { name: /^Browse vaults/ })).not.toBeInTheDocument();
  });

  it("still connects to a typed vault name without listing", async () => {
    render(() => <Connect />);
    fireEvent.input(vaultField(), { target: { value: "Typed" } });
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/dashboard"));
    expect(mockInvoke).toHaveBeenCalledWith("connect", { vault: "Typed", account: null });
    expect(listVaults).not.toHaveBeenCalled();
  });
});

describe("Connect account list", () => {
  const browseAccounts = () => screen.getByRole("button", { name: "Browse 1Password accounts" });

  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
  });

  it("lists the configured accounts and fills the field from a pick", async () => {
    listAccounts.mockResolvedValue([
      { url: "acme.1password.com", email: "alex@acme.example", account_uuid: "A1", user_uuid: "U1" },
      { url: "my.1password.com", email: "alex@home.example", account_uuid: "A2", user_uuid: "U2" },
    ]);
    render(() => <Connect />);
    await waitFor(() => expect(browseAccounts()).toBeEnabled());
    fireEvent.click(browseAccounts());
    expect(browseAccounts()).toHaveAttribute("aria-expanded", "true");
    fireEvent.click(screen.getByRole("option", { name: /alex@home\.example/ }));
    expect(accountField()).toHaveValue("my.1password.com");
    expect(screen.queryByRole("listbox")).not.toBeInTheDocument();
    expect(listVaults).not.toHaveBeenCalled();
  });

  it("disables browsing when the op CLI has no accounts", async () => {
    listAccounts.mockResolvedValue([]);
    render(() => <Connect />);
    await waitFor(() => expect(listAccounts).toHaveBeenCalled());
    expect(browseAccounts()).toBeDisabled();
    expect(browseAccounts()).toHaveAttribute("title", "No accounts are configured in the op CLI");
  });
});

describe("Connect recent logins", () => {
  const saveLogins = (logins: { vault: string; account: string | null }[]) =>
    localStorage.setItem("opca_saved_logins", JSON.stringify(logins));
  const recent = () => screen.queryByRole("region", { name: "Recent" });

  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    listAccounts.mockResolvedValue([]);
  });

  it("fills both fields from a row without listing", async () => {
    saveLogins([{ vault: "Clients", account: "acme.1password.com" }, { vault: "Home", account: null }]);
    render(() => <Connect />);
    fireEvent.click(await screen.findByRole("button", { name: /^Clients/ }));
    expect(vaultField()).toHaveValue("Clients");
    expect(accountField()).toHaveValue("acme.1password.com");
    fireEvent.click(screen.getByRole("button", { name: /^Home/ }));
    expect(vaultField()).toHaveValue("Home");
    expect(accountField()).toHaveValue("");
    expect(listVaults).not.toHaveBeenCalled();
  });

  it("forgets a login from its ×", async () => {
    saveLogins([{ vault: "Clients", account: "acme.1password.com" }, { vault: "Home", account: null }]);
    render(() => <Connect />);
    fireEvent.click(await screen.findByRole("button", { name: "Forget Clients in acme.1password.com" }));
    expect(screen.queryByRole("button", { name: /^Clients/ })).not.toBeInTheDocument();
    expect(vaultField()).toHaveValue("");
    expect(JSON.parse(localStorage.getItem("opca_saved_logins")!)).toEqual([{ vault: "Home", account: null }]);
  });

  it("shows the newest five, and nothing when there are none or when creating", async () => {
    saveLogins(Array.from({ length: 7 }, (_, i) => ({ vault: `V${i}`, account: null })));
    const { unmount } = render(() => <Connect />);
    await screen.findByRole("region", { name: "Recent" });
    expect(within(recent()!).getAllByRole("listitem").map((row) => row.textContent?.replace("×", "")))
      .toEqual(["V0default account", "V1default account", "V2default account", "V3default account", "V4default account"]);
    fireEvent.click(screen.getByRole("button", { name: "New CA in a new vault…" }));
    expect(recent()).not.toBeInTheDocument();
    unmount();

    localStorage.clear();
    render(() => <Connect />);
    expect(recent()).not.toBeInTheDocument();
  });

  it("records a login after connecting", async () => {
    connectsAs("Typed");
    render(() => <Connect />);
    fireEvent.input(vaultField(), { target: { value: "Typed" } });
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/dashboard"));
    expect(JSON.parse(localStorage.getItem("opca_saved_logins")!)).toEqual([{ vault: "Typed", account: null }]);
  });
});
