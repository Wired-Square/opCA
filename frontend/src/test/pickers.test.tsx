import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import VaultPicker from "../components/VaultPicker";
import VpnClientPicker from "../components/VpnClientPicker";
import Modal from "../components/Modal";
import type { CertListItem } from "../api/types";

const listVaults = vi.hoisted(() =>
  vi.fn(async () => [
    { id: "1", name: "Clients" },
    { id: "2", name: "Servers" },
  ]),
);
vi.mock("../api/vaults", async (actual) => ({
  ...(await actual<object>()),
  listVaults,
}));

const listbox = () => screen.queryByRole("listbox");

describe("VaultPicker", () => {
  function mount() {
    const onChange = vi.fn();
    const onModalClose = vi.fn();
    render(() => (
      <Modal open onClose={onModalClose}>
        <VaultPicker value="" onChange={onChange} />
      </Modal>
    ));
    fireEvent.click(screen.getByRole("button", { name: "Browse" }));
    return { onChange, onModalClose };
  }

  it("portals out of the dialog and closes on an outside mousedown", async () => {
    const { onModalClose } = mount();
    await screen.findByRole("option", { name: "Clients" });
    expect(screen.getByRole("dialog")).not.toContainElement(listbox());

    fireEvent.mouseDown(document.body);
    expect(listbox()).not.toBeInTheDocument();
    expect(onModalClose).not.toHaveBeenCalled();
  });

  it("selects a vault by keyboard", async () => {
    const { onChange } = mount();
    const servers = await screen.findByRole("option", { name: "Servers" });
    fireEvent.keyDown(servers, { key: "Enter" });
    expect(onChange).toHaveBeenCalledWith("Servers");
    expect(listbox()).not.toBeInTheDocument();
  });
});

describe("VpnClientPicker", () => {
  const cert = (serial: string, cn: string): CertListItem => ({
    serial, cn, title: cn, status: "Valid", cert_type: "vpnclient", expiry_date: null,
    key_type: null, key_size: null, ignored_at: null, superseded_by: null, expiring_soon: false,
  });

  it("toggles rows without closing", () => {
    const [selected, setSelected] = createSignal(new Set<string>());
    const onToggle = (c: CertListItem) => {
      const next = new Set(selected());
      if (!next.delete(c.serial!)) next.add(c.serial!);
      setSelected(next);
    };
    render(() => (
      <VpnClientPicker
        selected={selected()}
        clients={[cert("7", "alice"), cert("8", "bob")]}
        loading={false}
        onToggle={onToggle}
      />
    ));
    fireEvent.click(screen.getByRole("button", { name: /Select VPN/ }));
    const [alice, bob] = screen.getAllByRole("option");
    fireEvent.click(alice);
    fireEvent.keyDown(bob, { key: " " });
    expect(listbox()).toBeInTheDocument();
    expect(alice).toHaveAttribute("aria-selected", "true");
    expect(bob).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("button", { name: "2 selected" })).toBeInTheDocument();
  });
});
