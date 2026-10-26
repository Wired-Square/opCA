import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@solidjs/testing-library";
import CopyableValue from "../components/CopyableValue";

const writeText = vi.hoisted(() => vi.fn(async (_text: string) => {}));
vi.mock("@tauri-apps/plugin-clipboard-manager", () => ({ writeText }));

describe("CopyableValue", () => {
  beforeEach(() => writeText.mockReset());

  it("copies through the clipboard plugin and flashes Copied in place of the glyph", async () => {
    render(() => <CopyableValue value="example.com" mono />);
    const button = screen.getByRole("button", { name: "example.com" });
    expect(button.querySelector(".app-copy__glyph svg")).not.toBeNull();
    fireEvent.click(button);
    expect(writeText).toHaveBeenCalledWith("example.com");
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Copied"));
    expect(button).toHaveTextContent("example.comCopied");
    expect(button.querySelector(".app-copy__glyph svg")).toBeNull();
  });

  it("does not claim a copy the clipboard refused", async () => {
    writeText.mockRejectedValueOnce(new Error("denied"));
    render(() => <CopyableValue value="example.com" />);
    fireEvent.click(screen.getByRole("button", { name: "example.com" }));
    await Promise.resolve();
    await Promise.resolve();
    expect(screen.queryByText("Copied")).toBeNull();
  });

  it("shows a dash when there is nothing to copy", () => {
    render(() => <CopyableValue value={null} />);
    expect(screen.queryByRole("button")).toBeNull();
    expect(screen.getByText("—")).toBeInTheDocument();
  });
});
