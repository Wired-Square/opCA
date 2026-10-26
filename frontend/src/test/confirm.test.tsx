import { describe, it, expect, vi } from "vitest";
import { Show, createSignal } from "solid-js";
import { render, screen, fireEvent } from "@solidjs/testing-library";
import { Confirm, type ConfirmProps } from "@wired-square/kit";
import { createActing } from "../utils/acting";

/** opca's confirm dialogs are kit `Confirm`s with an acting verb; the wrappers
 * (Revoke/Ignore/ResignCa…) only test their own wiring on top of this. */

const confirm = () => screen.getByRole("button", { name: /^Confirm/ });
const reason = () => screen.getByPlaceholderText("Why?") as HTMLInputElement;

function mount({
  run = vi.fn(() => Promise.resolve()),
  children = "Really?",
  ...props
}: Partial<ConfirmProps> & { run?: (reason: string) => Promise<void> } = {}) {
  const onClose = vi.fn();
  render(() => {
    const acting = createActing();
    return (
      <Confirm
        title="Do the thing"
        verb={acting.verb("Confirm", "Confirming…")}
        onClose={onClose}
        act={acting.act(run)}
        {...props}
      >
        {children}
      </Confirm>
    );
  });
  return { onClose, run };
}

describe("Confirm with an acting verb", () => {
  it("renders the title and message in a modal dialog", () => {
    mount();
    expect(screen.getByRole("dialog")).toHaveAttribute("open");
    expect(screen.getByText("Do the thing")).toBeInTheDocument();
    expect(screen.getByText("Really?")).toBeInTheDocument();
  });

  it("names the act while it runs and holds Cancel", async () => {
    let finish!: () => void;
    const { onClose } = mount({ run: () => new Promise<void>((resolve) => (finish = resolve)) });
    confirm().click();
    expect(await screen.findByRole("button", { name: "Confirming…" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled();
    finish();
    await vi.waitFor(() => expect(onClose).toHaveBeenCalled());
  });

  it("runs the action then closes", async () => {
    const { run, onClose } = mount();
    confirm().click();
    await vi.waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(run).toHaveBeenCalledWith("");
  });

  it("stays open and shows the error as written when the action fails", async () => {
    const { onClose } = mount({ run: () => Promise.reject("vault locked") });
    confirm().click();
    expect(await screen.findByRole("alert")).toHaveTextContent("vault locked");
    expect(onClose).not.toHaveBeenCalled();
    expect(confirm()).toHaveTextContent("Confirm");
  });

  it("clears the reason and any error when reopened", async () => {
    const [open, setOpen] = createSignal(true);
    render(() => (
      <Show when={open()}>
        <Confirm
          title="t"
          verb="Confirm"
          reason={{ label: "Reason", placeholder: "Why?" }}
          onClose={() => setOpen(false)}
          act={createActing().act(() => Promise.reject("nope"))}
        >
          m
        </Confirm>
      </Show>
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
    it("a reason blocks confirm until non-blank, and is trimmed", async () => {
      const { run, onClose } = mount({ reason: { label: "Reason", placeholder: "Why?" } });
      expect(screen.getByLabelText("Reason")).toBe(reason());
      expect(confirm()).toBeDisabled();

      fireEvent.input(reason(), { target: { value: "   " } });
      expect(confirm()).toBeDisabled();

      fireEvent.input(reason(), { target: { value: "  because  " } });
      expect(confirm()).not.toBeDisabled();

      confirm().click();
      await vi.waitFor(() => expect(onClose).toHaveBeenCalled());
      expect(run).toHaveBeenCalledWith("because");
    });

    it("disabled gates the button independently of the reason", () => {
      const [ok, setOk] = createSignal(false);
      render(() => (
        <Confirm title="t" verb="Confirm" disabled={!ok()} onClose={() => {}} act={() => {}}>
          m
        </Confirm>
      ));
      expect(confirm()).toBeDisabled();

      setOk(true);
      expect(confirm()).not.toBeDisabled();
    });
  });

  it("is danger by default", () => {
    mount();
    expect(confirm()).toHaveClass("app-btn--danger");
  });

  it("takes the primary tone", () => {
    mount({ tone: "primary" });
    expect(confirm()).toHaveClass("app-btn--primary");
  });

  it("renders extra fields passed as children", () => {
    mount({ children: <label for="x">Extra field</label> });
    expect(screen.getByText("Extra field")).toBeInTheDocument();
  });
});
