import { describe, it, expect, vi } from "vitest";
import { createSignal } from "solid-js";
import { render, screen } from "@solidjs/testing-library";
import ResignCaDialog from "../components/ResignCaDialog";

const resignCa = vi.hoisted(() => vi.fn());
vi.mock("../api/ca", async (actual) => ({
  ...(await actual<object>()),
  resignCa,
}));

const confirmButton = () => screen.getByRole("button", { name: /Re-sign CA/ });
const daysInput = () => screen.getByLabelText("New validity (days)") as HTMLInputElement;

const setDays = (value: string) => {
  const input = daysInput();
  input.value = value;
  input.dispatchEvent(new Event("input", { bubbles: true }));
};

function mount() {
  const onClose = vi.fn();
  const onDone = vi.fn();
  return { onClose, onDone, ...render(() => <ResignCaDialog open onClose={onClose} onDone={onDone} />) };
}

describe("ResignCaDialog", () => {
  it("warns that the change cannot be undone", () => {
    mount();
    expect(screen.getByText(/cannot be recovered/)).toBeInTheDocument();
  });

  it("defaults to 3650 days and confirms with that value", async () => {
    resignCa.mockImplementation(() => Promise.resolve());
    const { onDone, onClose } = mount();
    expect(daysInput().value).toBe("3650");

    confirmButton().click();

    // Closing is the last step, so waiting on it covers the whole sequence.
    await vi.waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(resignCa).toHaveBeenCalledWith(3650);
    expect(onDone).toHaveBeenCalledWith(3650);
  });

  it("disables confirm for a non-positive or unparseable day count", () => {
    mount();
    for (const bad of ["0", "-5", ""]) {
      setDays(bad);
      expect(confirmButton(), `days = ${JSON.stringify(bad)}`).toBeDisabled();
    }

    setDays("365");
    expect(confirmButton()).not.toBeDisabled();
  });

  it("keeps the dialog open and shows the error when re-sign fails", async () => {
    // The Tauri layer rejects with a plain string, not an Error.
    resignCa.mockImplementation(() => Promise.reject("vault locked"));
    const { onDone, onClose } = mount();

    confirmButton().click();

    expect(await screen.findByRole("alert")).toHaveTextContent("vault locked");
    expect(onDone).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });

  it("resets the days field and any error when reopened", async () => {
    resignCa.mockImplementation(() => Promise.reject("vault locked"));
    const [open, setOpen] = createSignal(true);
    render(() => <ResignCaDialog open={open()} onClose={() => setOpen(false)} onDone={() => {}} />);

    setDays("1");
    confirmButton().click();
    expect(await screen.findByRole("alert")).toBeInTheDocument();

    setOpen(false);
    setOpen(true);

    expect(daysInput().value).toBe("3650");
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
