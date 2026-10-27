import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@solidjs/testing-library";
import CSR from "../pages/CSR";

const csrApi = vi.hoisted(() => ({
  listCsrs: vi.fn(),
  decodeCsr: vi.fn(),
  signCsr: vi.fn(),
}));
const signSubordinate = vi.hoisted(() => vi.fn());
vi.mock("../api/csr", async (actual) => ({ ...(await actual<object>()), ...csrApi }));
vi.mock("../api/subordinate", () => ({ signSubordinate }));
vi.mock("../api/ca", () => ({ getCaConfig: () => Promise.resolve({ days: 3650 }) }));

const PEM = "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----";

async function decoded() {
  render(() => <CSR />);
  fireEvent.click(screen.getByRole("button", { name: "Sign" }));
  fireEvent.input(screen.getByPlaceholderText("Paste CSR PEM here..."), { target: { value: PEM } });
  fireEvent.click(screen.getByRole("button", { name: "Decode CSR" }));
  await screen.findByLabelText("Certificate Type");
}

function chooseType(value: string) {
  fireEvent.change(screen.getByLabelText("Certificate Type"), { target: { value } });
}

function daysField() {
  return screen.getByLabelText("Validity (days)") as HTMLInputElement;
}

describe("CSR Sign tab", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    csrApi.listCsrs.mockResolvedValue([]);
    csrApi.decodeCsr.mockResolvedValue({ cn: "Broker CA", subject: "CN=Broker CA", alt_names: [] });
  });

  it("asks a subordinate CA for its permitted domains instead of a CN and SANs", async () => {
    await decoded();
    expect(screen.queryByLabelText("Permitted Domains")).not.toBeInTheDocument();

    chooseType("subordinateca");

    expect(screen.getByLabelText("Permitted Domains")).toBeInTheDocument();
    expect(screen.queryByText("Common Name")).not.toBeInTheDocument();
    expect(screen.queryByText("Subject Alternative Names")).not.toBeInTheDocument();
    await vi.waitFor(() => expect(daysField().value).toBe("90"));
    expect(screen.getByRole("button", { name: "Sign CSR" })).toBeDisabled();
  });

  it("signs a subordinate through its own command with one domain per line", async () => {
    signSubordinate.mockResolvedValue({
      broker: { subordinate_serial: "42" },
      cert_pem: "-----BEGIN CERTIFICATE-----",
    });
    await decoded();
    chooseType("subordinateca");
    fireEvent.input(screen.getByLabelText("Permitted Domains"), {
      target: { value: "home.arpa\n  lab.example.com\n\n" },
    });
    await vi.waitFor(() => expect(daysField().value).toBe("90"));

    fireEvent.click(screen.getByRole("button", { name: "Sign CSR" }));

    await screen.findByText("Certificate signed successfully (serial 42).");
    expect(signSubordinate).toHaveBeenCalledWith({
      csr_pem: PEM,
      domains: ["home.arpa", "lab.example.com"],
      days: 90,
    });
    expect(csrApi.signCsr).not.toHaveBeenCalled();
  });

  it("signs other types through the generic command", async () => {
    csrApi.signCsr.mockResolvedValue({ cert: { serial: "43" }, cert_pem: "-----BEGIN CERTIFICATE-----" });
    await decoded();
    chooseType("device");

    fireEvent.click(screen.getByRole("button", { name: "Sign CSR" }));

    await screen.findByText("Certificate signed successfully (serial 43).");
    expect(csrApi.signCsr).toHaveBeenCalledWith(
      expect.objectContaining({ csr_pem: PEM, csr_type: "device", cn: "Broker CA" }),
    );
    expect(signSubordinate).not.toHaveBeenCalled();
  });

  it("does not offer Apple Development, whose certificate Apple issues", async () => {
    await decoded();
    const types = Array.from((screen.getByLabelText("Certificate Type") as HTMLSelectElement).options, (o) => o.value);
    expect(types).toContain("device");
    expect(types).not.toContain("appledev");
  });
});
