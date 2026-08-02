import { describe, it, expect, vi } from "vitest";
import { createSignal } from "solid-js";
import { render, screen, fireEvent } from "@solidjs/testing-library";
import ResignCaDialog from "../components/ResignCaDialog";

/** A thin wrapper over ConfirmDialog — the acting/error/reset behaviour is
 * covered in confirm-dialog.test. What is specific here is the days field. */

const resignCa = vi.hoisted(() => vi.fn());
vi.mock("../api/ca", async (actual) => ({
  ...(await actual<object>()),
  resignCa,
}));

const confirmButton = () => screen.getByRole("button", { name: /Re-sign CA/ });
const daysInput = () => screen.getByLabelText("New validity (days)") as HTMLInputElement;
const setDays = (value: string) => fireEvent.input(daysInput(), { target: { value } });

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

  it("resets the days field when reopened", async () => {
    resignCa.mockImplementation(() => Promise.reject("vault locked"));
    const [open, setOpen] = createSignal(true);
    render(() => <ResignCaDialog open={open()} onClose={() => setOpen(false)} onDone={() => {}} />);

    setDays("1");
    confirmButton().click();
    expect(await screen.findByRole("alert")).toBeInTheDocument();

    setOpen(false);
    setOpen(true);

    expect(daysInput().value).toBe("3650");
  });
});
