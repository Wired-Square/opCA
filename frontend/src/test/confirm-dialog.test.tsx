import { describe, it, expect, vi } from "vitest";
import { createSignal } from "solid-js";
import { render, screen, fireEvent } from "@solidjs/testing-library";
import ConfirmDialog from "../components/ConfirmDialog";

/** The shared state machine every confirm dialog inherits. The wrappers
 * (Revoke/Ignore/ResignCa) only test their own wiring on top of this. */

const confirm = () => screen.getByRole("button", { name: /^Confirm/ });
const reason = () => screen.getByPlaceholderText("Why?") as HTMLInputElement;

function mount(props: Partial<Parameters<typeof ConfirmDialog>[0]> = {}) {
  const onClose = vi.fn();
  const onConfirm = vi.fn(() => Promise.resolve());
  const rendered = render(() => (
    <ConfirmDialog
      open
      title="Do the thing"
      message="Really?"
      confirmLabel="Confirm"
      actingLabel="Confirming…"
      onClose={onClose}
      onConfirm={onConfirm}
      {...props}
    />
  ));
  return { onClose, onConfirm, ...rendered };
}

describe("ConfirmDialog", () => {
  it("renders the title and message", () => {
    mount();
    expect(screen.getByText("Do the thing")).toBeInTheDocument();
    expect(screen.getByText("Really?")).toBeInTheDocument();
  });

  it("runs the action then closes", async () => {
    const { onConfirm, onClose } = mount();
    confirm().click();
    await vi.waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(onConfirm).toHaveBeenCalledWith("");
  });

  it("stays open and shows the error when the action fails", async () => {
    const onClose = vi.fn();
    render(() => (
      <ConfirmDialog
        open
        title="t"
        message="m"
        confirmLabel="Confirm"
        actingLabel="…"
        onClose={onClose}
        onConfirm={() => Promise.reject("vault locked")}
      />
    ));

    confirm().click();

    expect(await screen.findByRole("alert")).toHaveTextContent("vault locked");
    expect(onClose).not.toHaveBeenCalled();
  });

  it("clears the reason and any error when reopened", async () => {
    const [open, setOpen] = createSignal(true);
    render(() => (
      <ConfirmDialog
        open={open()}
        title="t"
        message="m"
        confirmLabel="Confirm"
        actingLabel="…"
        requireReason
        reasonPlaceholder="Why?"
        onClose={() => setOpen(false)}
        onConfirm={() => Promise.reject("nope")}
      />
    ));

    fireEvent.input(reason(), { target: { value: "typo" } });
    confirm().click();
    expect(await screen.findByRole("alert")).toBeInTheDocument();

    setOpen(false);
    setOpen(true);

    expect(reason().value).toBe("");
    expect(screen.queryByRole("alert")).toBeNull();
  });

  describe("gating", () => {
    it("requireReason blocks confirm until non-blank, and trims it", async () => {
      const { onConfirm, onClose } = mount({
        requireReason: true,
        reasonPlaceholder: "Why?",
      });
      expect(confirm()).toBeDisabled();

      fireEvent.input(reason(), { target: { value: "   " } });
      expect(confirm()).toBeDisabled();

      fireEvent.input(reason(), { target: { value: "  because  " } });
      expect(confirm()).not.toBeDisabled();

      confirm().click();
      await vi.waitFor(() => expect(onClose).toHaveBeenCalled());
      expect(onConfirm).toHaveBeenCalledWith("because");
    });

    it("canConfirm gates the button independently of the reason", () => {
      const [ok, setOk] = createSignal(false);
      mount({ canConfirm: () => ok() });
      expect(confirm()).toBeDisabled();

      setOk(true);
      expect(confirm()).not.toBeDisabled();
    });
  });

  it("uses the danger styling when asked", () => {
    const { container } = mount({ danger: true });
    expect(container.querySelector(".btn-danger")).toBeInTheDocument();
  });

  it("renders extra fields passed as children", () => {
    mount({ children: <label for="x">Extra field</label> });
    expect(screen.getByText("Extra field")).toBeInTheDocument();
  });
});
