import { describe, it, expect, vi, beforeEach } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { tauriInvoke } from "../api/tauri";
import { appState } from "../stores/app";

const mockInvoke = vi.mocked(invoke);

describe("tauriInvoke", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });

  it("returns the result from invoke on success", async () => {
    mockInvoke.mockResolvedValueOnce({ cn: "Test CA" });

    const result = await tauriInvoke<{ cn: string }>("get_ca_info");
    expect(result).toEqual({ cn: "Test CA" });
    expect(mockInvoke).toHaveBeenCalledWith("get_ca_info", undefined);
  });

  it("passes arguments through to invoke", async () => {
    mockInvoke.mockResolvedValueOnce(null);

    await tauriInvoke("create_cert", { cn: "example.com", cert_type: "webserver" });
    expect(mockInvoke).toHaveBeenCalledWith("create_cert", {
      cn: "example.com",
      cert_type: "webserver",
    });
  });

  it("sets app error state and throws on failure", async () => {
    mockInvoke.mockRejectedValueOnce("Vault not found");

    await expect(tauriInvoke("get_ca_info")).rejects.toThrow("Vault not found");
    expect(appState.error).toBe("Vault not found");
  });

  it("clears previous error on new invocation", async () => {
    mockInvoke.mockRejectedValueOnce("first error");
    await expect(tauriInvoke("get_ca_info")).rejects.toThrow();

    mockInvoke.mockResolvedValueOnce("ok");
    await tauriInvoke("get_ca_info");
    expect(appState.error).toBeNull();
  });
});
