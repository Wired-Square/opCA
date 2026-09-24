import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@solidjs/testing-library";
import RevokeCertDialog from "../components/RevokeCertDialog";
import IgnoreCertDialog from "../components/IgnoreCertDialog";
import RekeyDialog from "../components/RekeyDialog";

/** These are thin wrappers over ConfirmDialog, so only their own wiring is
 * tested here — the acting/error/reset behaviour lives in confirm-dialog.test. */

const revokeCert = vi.hoisted(() => vi.fn());
const ignoreCert = vi.hoisted(() => vi.fn());
vi.mock("../api/certs", async (actual) => ({
  ...(await actual<object>()),
  revokeCert,
  ignoreCert,
}));

const CERT = { serial: "131", cn: "vpn.example.com" };

describe("RevokeCertDialog", () => {
  it("names the certificate and warns it is permanent", () => {
    render(() => <RevokeCertDialog open {...CERT} onClose={() => {}} onDone={() => {}} />);
    expect(screen.getByText("vpn.example.com")).toBeInTheDocument();
    expect(screen.getByText(/cannot be undone/)).toBeInTheDocument();
  });

  it("revokes by serial and reports back", async () => {
    revokeCert.mockImplementation(() => Promise.resolve());
    const onDone = vi.fn();
    const onClose = vi.fn();
    render(() => <RevokeCertDialog open {...CERT} onClose={onClose} onDone={onDone} />);

    screen.getByRole("button", { name: /^Revoke/ }).click();

    await vi.waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(revokeCert).toHaveBeenCalledWith("131");
    expect(onDone).toHaveBeenCalled();
  });
});

describe("IgnoreCertDialog", () => {
  it("names the certificate and asks for a reason", () => {
    render(() => <IgnoreCertDialog open {...CERT} onClose={() => {}} onDone={() => {}} />);
    expect(screen.getByText("vpn.example.com")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("Why is this being ignored?")).toBeInTheDocument();
  });

  it("ignores with the serial and the trimmed reason", async () => {
    ignoreCert.mockImplementation(() => Promise.resolve());
    const onDone = vi.fn();
    const onClose = vi.fn();
    render(() => <IgnoreCertDialog open {...CERT} onClose={onClose} onDone={onDone} />);

    fireEvent.input(screen.getByPlaceholderText("Why is this being ignored?"), {
      target: { value: "  decommissioned  " },
    });
    screen.getByRole("button", { name: /Confirm Ignore/ }).click();

    await vi.waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(ignoreCert).toHaveBeenCalledWith("131", "decommissioned");
    expect(onDone).toHaveBeenCalled();
  });
});

describe("RekeyDialog", () => {
  function renderRekey(onConfirm: (k: unknown) => Promise<void>) {
    const onClose = vi.fn();
    render(() => (
      <RekeyDialog open title="Rekey Certificate" message="Rekey it?" onClose={onClose} onConfirm={onConfirm} />
    ));
    return onClose;
  }

  it("keeps the current key algorithm by default", async () => {
    const onConfirm = vi.fn(() => Promise.resolve());
    const onClose = renderRekey(onConfirm);

    screen.getByRole("button", { name: /^Rekey/ }).click();

    await vi.waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(onConfirm).toHaveBeenCalledWith(null);
  });

  it("passes a chosen key algorithm", async () => {
    const onConfirm = vi.fn(() => Promise.resolve());
    const onClose = renderRekey(onConfirm);

    fireEvent.change(screen.getByLabelText("Key Type"), { target: { value: "ec-p256" } });
    screen.getByRole("button", { name: /^Rekey/ }).click();

    await vi.waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(onConfirm).toHaveBeenCalledWith("ec-p256");
  });
});
