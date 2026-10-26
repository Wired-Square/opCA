import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@solidjs/testing-library";
import { Dialog } from "@wired-square/kit";
import ActionMenu from "../components/ActionMenu";

const trigger = (name = "Actions") => screen.getByRole("button", { name });
const items = () => screen.queryAllByRole("menuitem");

function mount() {
  const renew = vi.fn();
  const exportPem = vi.fn();
  const revoke = vi.fn();
  render(() => (
    <ActionMenu
      items={[
        { label: "Renew", onSelect: renew },
        { label: "Export", onSelect: exportPem, disabled: true },
        { label: "Revoke", onSelect: revoke, danger: true },
      ]}
    />
  ));
  return { renew, exportPem, revoke };
}

describe("ActionMenu", () => {
  it("draws the kit's ⋮ trigger and builds no items until opened", () => {
    mount();
    expect(trigger()).toHaveTextContent("⋮");
    expect(items()).toHaveLength(0);
  });

  it("opens on click and focuses the first item", () => {
    mount();
    fireEvent.click(trigger());
    expect(trigger()).toHaveAttribute("aria-expanded", "true");
    expect(items().map((i) => i.textContent)).toEqual(["Renew", "Export", "Revoke"]);
    expect(items()[0]).toHaveFocus();
  });

  it("takes a named label", () => {
    render(() => <ActionMenu aria-label="Certificate actions" items={[]} />);
    expect(trigger("Certificate actions")).toBeInTheDocument();
  });

  it("arrow keys reach a disabled item and wrap", () => {
    mount();
    fireEvent.click(trigger());
    fireEvent.keyDown(items()[0], { key: "ArrowDown" });
    expect(items()[1]).toHaveFocus();
    fireEvent.keyDown(items()[1], { key: "End" });
    expect(items()[2]).toHaveFocus();
    fireEvent.keyDown(items()[2], { key: "ArrowDown" });
    expect(items()[0]).toHaveFocus();
  });

  it("marks a disabled item and a danger item, and a disabled one does nothing", () => {
    const { exportPem } = mount();
    fireEvent.click(trigger());
    const [, exported, revoke] = items();
    expect(exported).toHaveAttribute("aria-disabled", "true");
    expect(revoke).toHaveClass("app-menu__item--danger");

    fireEvent.click(exported);
    expect(exportPem).not.toHaveBeenCalled();
    expect(trigger()).toHaveAttribute("aria-expanded", "true");
  });

  it("selecting an item runs it, closes, and returns focus to the trigger", () => {
    const { revoke } = mount();
    fireEvent.click(trigger());
    fireEvent.click(screen.getByRole("menuitem", { name: "Revoke" }));
    expect(revoke).toHaveBeenCalledOnce();
    expect(items()).toHaveLength(0);
    expect(trigger()).toHaveFocus();
  });

  it("Escape inside a dialog closes only the menu", () => {
    const onClose = vi.fn();
    render(() => (
      <Dialog title="t" onClose={onClose}>
        <ActionMenu items={[{ label: "Renew", onSelect: () => {} }]} />
      </Dialog>
    ));
    fireEvent.click(trigger());
    const escape = new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true });
    items()[0].dispatchEvent(escape);
    expect(items()).toHaveLength(0);
    expect(escape.defaultPrevented).toBe(true);
    expect(screen.getByRole("dialog")).toHaveAttribute("open");
    expect(onClose).not.toHaveBeenCalled();
  });
});
