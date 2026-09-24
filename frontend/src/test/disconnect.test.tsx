import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@solidjs/testing-library";
import { invoke } from "@tauri-apps/api/core";
import type { Component } from "solid-js";
import Sidebar from "../components/layout/Sidebar";
import Header from "../components/layout/Header";
import { appState, setAppState } from "../stores/app";

const navigate = vi.hoisted(() => vi.fn());
vi.mock("@solidjs/router", () => ({
  A: (props: { href: string; children: unknown }) => <a href={props.href}>{props.children as never}</a>,
  useLocation: () => ({ pathname: "/dashboard" }),
  useNavigate: () => navigate,
}));
vi.mock("@tauri-apps/plugin-shell", () => ({ open: vi.fn() }));

describe.each([
  ["sidebar", Sidebar],
  ["header", Header],
] as [string, Component][])("%s Disconnect", (_name, Layout) => {
  beforeEach(() => {
    vi.clearAllMocks();
    setAppState({ connected: true, vaultState: "valid_ca", vault: "CA-Test", account: "acct" });
  });

  it("releases the backend connection before leaving", async () => {
    render(() => <Layout />);
    fireEvent.click(screen.getByRole("button", { name: "Disconnect" }));

    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/"));
    expect(vi.mocked(invoke)).toHaveBeenCalledWith("disconnect", undefined);
    expect(appState).toMatchObject({ connected: false, vaultState: "disconnected", vault: "" });
  });
});
