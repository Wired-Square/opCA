import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@solidjs/testing-library";
import KebabMenu from "../components/KebabMenu";
import Modal from "../components/Modal";

const trigger = () => screen.getByRole("button", { name: "Actions" });
const menu = () => screen.queryByRole("menu");
const items = () => screen.getAllByRole("menuitem");

function mount() {
  const renew = vi.fn();
  const revoke = vi.fn();
  render(() => (
    <KebabMenu
      items={[
        { label: "Renew", onSelect: renew },
        { label: "Export", onSelect: () => {}, disabled: true },
        { label: "Revoke", onSelect: revoke, danger: true },
      ]}
    />
  ));
  return { renew, revoke };
}

describe("KebabMenu", () => {
  it("opens on click and focuses the first item", () => {
    mount();
    fireEvent.click(trigger());
    expect(menu()).toBeInTheDocument();
    expect(trigger()).toHaveAttribute("aria-expanded", "true");
    expect(items()[0]).toHaveFocus();
  });

  it("arrow keys skip disabled items and wrap", () => {
    mount();
    fireEvent.click(trigger());
    fireEvent.keyDown(items()[0], { key: "ArrowDown" });
    expect(items()[2]).toHaveFocus();
    fireEvent.keyDown(items()[2], { key: "ArrowDown" });
    expect(items()[0]).toHaveFocus();
    fireEvent.keyDown(items()[0], { key: "End" });
    expect(items()[2]).toHaveFocus();
  });

  it("selecting an item runs it, closes, and returns focus to the trigger", () => {
    const { revoke } = mount();
    fireEvent.click(trigger());
    fireEvent.click(screen.getByRole("menuitem", { name: "Revoke" }));
    expect(revoke).toHaveBeenCalledOnce();
    expect(menu()).not.toBeInTheDocument();
    expect(trigger()).toHaveFocus();
  });

  it("closes on Escape and on an outside mousedown", () => {
    mount();
    fireEvent.click(trigger());
    fireEvent.keyDown(window, { key: "Escape" });
    expect(menu()).not.toBeInTheDocument();

    fireEvent.click(trigger());
    fireEvent.mouseDown(document.body);
    expect(menu()).not.toBeInTheDocument();
  });

  it("Escape inside a modal closes only the menu", () => {
    const onClose = vi.fn();
    render(() => (
      <Modal open onClose={onClose}>
        <KebabMenu items={[{ label: "Renew", onSelect: () => {} }]} />
      </Modal>
    ));
    fireEvent.click(trigger());
    fireEvent.keyDown(items()[0], { key: "Escape" });
    expect(menu()).not.toBeInTheDocument();
    expect(onClose).not.toHaveBeenCalled();
  });
});
