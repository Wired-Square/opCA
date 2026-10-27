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
});
