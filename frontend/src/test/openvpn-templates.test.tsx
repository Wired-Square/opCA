import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@solidjs/testing-library";
import OpenVPN from "../pages/OpenVPN";

const getOpenVpnTemplate = vi.hoisted(() => vi.fn());
vi.mock("../api/openvpn", async (actual) => ({
  ...(await actual<object>()),
  listOpenVpnTemplates: () => Promise.resolve([
    { name: "office", updated_date: null },
    { name: "home", updated_date: null },
  ]),
  listOpenVpnVaultTemplates: () => Promise.resolve([]),
  listVpnCerts: () => Promise.resolve([]),
  listOpenVpnProfiles: () => Promise.resolve([]),
  getOpenVpnTemplate,
}));
vi.mock("@solidjs/router", () => ({ useSearchParams: () => [{}] }));

describe("OpenVPN templates", () => {
  it("selecting a template keeps the editor in place while it loads", async () => {
    let releaseHome!: (detail: { content: string }) => void;
    getOpenVpnTemplate.mockImplementation((name: string) =>
      name === "office"
        ? Promise.resolve({ content: "office config" })
        : new Promise((resolve) => { releaseHome = resolve; }),
    );
    render(() => <OpenVPN />);
    fireEvent.click(screen.getByRole("button", { name: "Templates" }));

    fireEvent.click(await screen.findByText("office"));
    const editor = await screen.findByDisplayValue("office config");

    fireEvent.click(screen.getByText("home"));
    expect(screen.queryByText("Loading template...")).not.toBeInTheDocument();
    expect(editor).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save Template" })).toBeDisabled();

    releaseHome({ content: "home config" });
    expect(await screen.findByDisplayValue("home config")).toBe(editor);
  });

  function deferredTemplates() {
    const release: Record<string, (detail: { content: string }) => void> = {};
    getOpenVpnTemplate.mockImplementation((name: string) =>
      new Promise((resolve) => { release[name] = resolve; }),
    );
    return release;
  }

  it("a slower earlier load doesn't replace the selected template", async () => {
    const release = deferredTemplates();
    render(() => <OpenVPN />);
    fireEvent.click(screen.getByRole("button", { name: "Templates" }));

    fireEvent.click(await screen.findByText("office"));
    fireEvent.click(screen.getByText("home"));
    release.home({ content: "home config" });
    const editor = await screen.findByDisplayValue("home config");

    release.office({ content: "office config" });
    await Promise.resolve();
    expect(editor).toHaveValue("home config");
  });

  it("stays loading until the selected template's load finishes", async () => {
    const release = deferredTemplates();
    render(() => <OpenVPN />);
    fireEvent.click(screen.getByRole("button", { name: "Templates" }));
    fireEvent.click(await screen.findByText("office"));
    release.office({ content: "office config" });
    const editor = await screen.findByDisplayValue("office config");

    fireEvent.click(screen.getByText("home"));
    fireEvent.click(screen.getByText("office"));
    release.home({ content: "home config" });
    await Promise.resolve();
    expect(screen.getByRole("button", { name: "Save Template" })).toBeDisabled();

    release.office({ content: "office config v2" });
    expect(await screen.findByDisplayValue("office config v2")).toBe(editor);
    expect(screen.getByRole("button", { name: "Save Template" })).toBeEnabled();
  });
});
