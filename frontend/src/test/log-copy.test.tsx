import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@solidjs/testing-library";
import Log from "../pages/Log";

const writeText = vi.hoisted(() => vi.fn(async (_text: string) => {}));
vi.mock("@tauri-apps/plugin-clipboard-manager", () => ({ writeText }));
vi.mock("../api/logs", () => ({
  getLogContents: async () => "[INFO] one\n[WARN] two",
  getLogPath: async () => "/tmp/opca.log",
}));

describe("Log copy all", () => {
  beforeEach(() => writeText.mockReset());

  it("copies the whole log and says Copied only once the write has landed", async () => {
    let land!: () => void;
    writeText.mockImplementationOnce(() => new Promise<void>((resolve) => (land = resolve)));
    render(() => <Log />);
    fireEvent.click(await screen.findByRole("button", { name: "Copy all" }));
    expect(writeText).toHaveBeenCalledWith("[INFO] one\n[WARN] two");
    expect(screen.queryByText("Copied")).toBeNull();
    land();
    expect(await screen.findByRole("status")).toHaveTextContent("Copied");
    expect(screen.getByRole("button", { name: "Copy all" })).toHaveTextContent("Copied");
  });
});
