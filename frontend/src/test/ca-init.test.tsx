import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@solidjs/testing-library";
import CA from "../pages/CA";

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

function field(label: string) {
  return screen.getByText(label).nextElementSibling as HTMLInputElement;
}

describe("CA init tab", () => {
  it("requires a Common Name and sends it with the default lifetimes", async () => {
    Object.defineProperty(window, "location", { value: { reload: vi.fn() }, configurable: true });
    render(() => <CA />);
    const [, button] = screen.getAllByRole("button", { name: "Initialise CA" });
    expect(button).toBeDisabled();

    fireEvent.input(field("Common Name"), { target: { value: "Example Root CA" } });
    fireEvent.click(button);

    await waitFor(() => expect(initCa).toHaveBeenCalled());
    expect(initCa.mock.calls[0][0]).toMatchObject({
      cn: "Example Root CA",
      ca_days: 3650,
      days: 365,
      crl_days: 30,
    });
  });

  it("does not retrieve the CA from a vault without one", () => {
    render(() => <CA />);
    expect(getCaInfo).not.toHaveBeenCalled();
    expect(getCaConfig).not.toHaveBeenCalled();
  });
});
