import { describe, it, expect, vi } from "vitest";
import { Show } from "solid-js";
import { render, screen, fireEvent } from "@solidjs/testing-library";
import DatabaseRecoveryDialog, { recoveryOpen, setRecoveryOpen } from "../components/DatabaseRecoveryDialog";

const restoreLocalBackup = vi.hoisted(() => vi.fn());
vi.mock("../api/localBackups", () => ({
  getLocalBackups: async () => ({
    enabled: true,
    dir: "/backups",
    database_error: "bad header",
    backups: [{ path: "/backups/a", taken_at: "2026-10-25T00:00:00Z", size: 2048, source: null, cert_count: 3 }],
  }),
  restoreLocalBackup,
}));
vi.mock("@solidjs/router", () => ({ useNavigate: () => vi.fn() }));

function mount() {
  setRecoveryOpen(true);
  render(() => (
    <Show when={recoveryOpen()}>
      <DatabaseRecoveryDialog />
    </Show>
  ));
}

const close = () => screen.getByRole("button", { name: "Close" });

describe("DatabaseRecoveryDialog", () => {
  it("closes from its own Close button", async () => {
    mount();
    await screen.findByRole("button", { name: "Restore selected backup" });
    fireEvent.click(close());
    expect(recoveryOpen()).toBe(false);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("holds Close while a restore runs", async () => {
    restoreLocalBackup.mockReturnValue(new Promise(() => {}));
    mount();
    fireEvent.click(await screen.findByRole("button", { name: "Restore selected backup" }));
    fireEvent.click(screen.getByRole("button", { name: "Restore" }));
    expect(await screen.findByRole("button", { name: "Restoring…" })).toBeDisabled();
    expect(close()).toBeDisabled();
  });
});
