import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@solidjs/testing-library";
import CopyPrivateKeyDialog from "../components/CopyPrivateKeyDialog";

vi.mock("../api/vault-backup", () => ({ generatePassword: () => Promise.resolve("gen-pass-123") }));

function renderDialog(onCopy = vi.fn().mockResolvedValue(undefined), onClose = vi.fn()) {
  render(() => <CopyPrivateKeyDialog open label="www.example.com" onClose={onClose} onCopy={onCopy} />);
  return { onCopy, onClose };
}

const copyButton = () => screen.getByRole("button", { name: /^Copy/ });
const type = (label: string, value: string) =>
  fireEvent.input(screen.getByLabelText(label), { target: { value } });

describe("CopyPrivateKeyDialog", () => {
  it("keeps the clipboard warning and copies unencrypted by default", async () => {
    const { onCopy, onClose } = renderDialog();
    expect(screen.getByText(/Anything that can read your clipboard/)).toBeInTheDocument();
    copyButton().click();
    await vi.waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(onCopy).toHaveBeenCalledWith(undefined);
  });

  it("cancelling copies nothing", () => {
    const { onCopy, onClose } = renderDialog();
    screen.getByRole("button", { name: "Cancel" }).click();
    expect(onClose).toHaveBeenCalled();
    expect(onCopy).not.toHaveBeenCalled();
  });

  it("holds Copy until the passphrases match", async () => {
    const { onCopy, onClose } = renderDialog();
    fireEvent.change(screen.getByLabelText("Encrypt with a passphrase"), { target: { checked: true } });
    expect(copyButton()).toBeDisabled();

    type("Passphrase", "s3cret");
    type("Confirm passphrase", "s3cre");
    expect(screen.getByLabelText("Confirm passphrase")).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByText(/Passphrases don't match/)).toBeInTheDocument();
    expect(copyButton()).toBeDisabled();

    type("Confirm passphrase", "s3cret");
    expect(copyButton()).toBeEnabled();
    copyButton().click();
    await vi.waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(onCopy).toHaveBeenCalledWith("s3cret");
  });

  it("generates a passphrase and shows it", async () => {
    renderDialog();
    fireEvent.change(screen.getByLabelText("Encrypt with a passphrase"), { target: { checked: true } });
    screen.getByRole("button", { name: "Generate" }).click();
    await vi.waitFor(() =>
      expect(screen.getByLabelText("Passphrase")).toHaveValue("gen-pass-123"),
    );
    expect(screen.getByLabelText("Passphrase")).toHaveAttribute("type", "text");
    expect(copyButton()).toBeEnabled();
  });

  it("shows a failed copy in the dialog instead of closing", async () => {
    const { onClose } = renderDialog(vi.fn().mockRejectedValue(new Error("No private key stored")));
    copyButton().click();
    await vi.waitFor(() => expect(screen.getByText(/No private key stored/)).toBeInTheDocument());
    expect(onClose).not.toHaveBeenCalled();
  });
});
