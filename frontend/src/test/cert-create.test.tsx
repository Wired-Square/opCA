import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@solidjs/testing-library";
import CertCreate from "../pages/CertCreate";

const createCert = vi.hoisted(() => vi.fn());
vi.mock("../api/certs", async (actual) => ({ ...(await actual<object>()), createCert }));
vi.mock("@solidjs/router", () => ({ useNavigate: () => vi.fn() }));
vi.mock("../api/ca", () => ({ getCaConfig: () => Promise.resolve({ days: 3650 }) }));

function sanField() {
  return screen.getByLabelText("Subject Alternative Names") as HTMLInputElement;
}

function daysField() {
  return screen.getByLabelText("Validity (days)") as HTMLInputElement;
}

function type(input: HTMLInputElement, value: string) {
  fireEvent.input(input, { target: { value } });
}

describe("CertCreate", () => {
  it("defaults to a Web Server certificate with an EC P-256 key", () => {
    render(() => <CertCreate />);
    expect((screen.getByLabelText("Certificate Type") as HTMLSelectElement).value).toBe("webserver");
    expect((screen.getByLabelText("Key Type") as HTMLSelectElement).value).toBe("ec-p256");
  });

  it("flags an invalid SAN as you type and refuses to add it", () => {
    render(() => <CertCreate />);
    type(sanField(), "10.0.0.300");
    expect(sanField()).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByText(/Not a valid IPv4 address/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add" })).toBeDisabled();
  });

  it("confirms a valid SAN's kind and tags the chip", () => {
    render(() => <CertCreate />);
    for (const [value, label, tag] of [
      ["10.0.0.30", "IPv4 address", "IP"],
      ["ops@example.com", "Email address", "Email"],
      ["spiffe://prod/web", "URI", "URI"],
    ]) {
      type(sanField(), value);
      expect(sanField()).not.toHaveAttribute("aria-invalid");
      expect(screen.getByText(`✓ ${label}`)).toBeInTheDocument();
      fireEvent.keyDown(sanField(), { key: "Enter" });
      const chip = screen.getByRole("button", { name: `Remove ${value}` }).parentElement!;
      expect(chip.querySelector(".san-kind")).toHaveTextContent(tag);
    }
  });

  it("sends the key algorithm and SANs", async () => {
    createCert.mockResolvedValue({});
    render(() => <CertCreate />);
    fireEvent.input(screen.getByLabelText("Common Name"), { target: { value: "www.example.com" } });
    fireEvent.change(screen.getByLabelText("Key Type"), { target: { value: "rsa-4096" } });
    type(sanField(), "10.0.0.30");
    fireEvent.keyDown(sanField(), { key: "Enter" });
    await vi.waitFor(() => expect(daysField().value).toBe("825"));
    fireEvent.click(screen.getByRole("button", { name: /Create/ }));
    await vi.waitFor(() =>
      expect(createCert).toHaveBeenCalledWith({
        cn: "www.example.com",
        cert_type: "webserver",
        alt_names: ["10.0.0.30"],
        key_algorithm: "rsa-4096",
        days: 825,
      }),
    );
  });

  it("prefills the CA's lifetime, capped at 825 days for server types", async () => {
    render(() => <CertCreate />);
    await vi.waitFor(() => expect(daysField().value).toBe("825"));
    fireEvent.change(screen.getByLabelText("Certificate Type"), { target: { value: "device" } });
    expect(daysField().value).toBe("3650");
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("warns but still submits a server lifetime over 825 days", async () => {
    createCert.mockResolvedValue({});
    render(() => <CertCreate />);
    fireEvent.input(screen.getByLabelText("Common Name"), { target: { value: "www.example.com" } });
    await vi.waitFor(() => expect(daysField().value).toBe("825"));
    type(daysField(), "900");
    expect(screen.getByRole("status")).toHaveTextContent("macOS and iOS will reject");
    fireEvent.click(screen.getByRole("button", { name: /Create/ }));
    await vi.waitFor(() =>
      expect(createCert).toHaveBeenCalledWith(expect.objectContaining({ days: 900 })),
    );
  });

  it("leaves a cleared lifetime to the backend default", async () => {
    createCert.mockResolvedValue({});
    render(() => <CertCreate />);
    fireEvent.input(screen.getByLabelText("Common Name"), { target: { value: "www.example.com" } });
    await vi.waitFor(() => expect(daysField().value).toBe("825"));
    type(daysField(), "");
    fireEvent.click(screen.getByRole("button", { name: /Create/ }));
    await vi.waitFor(() =>
      expect(createCert).toHaveBeenLastCalledWith(expect.objectContaining({ days: undefined })),
    );
  });
});
