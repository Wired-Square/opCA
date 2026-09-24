import { describe, it, expect, vi, beforeEach } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { tauriInvoke } from "../api/tauri";

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

  it("normalises a string rejection into an Error", async () => {
    mockInvoke.mockRejectedValueOnce("Vault not found");

    await expect(tauriInvoke("get_ca_info")).rejects.toThrow("Vault not found");
  });

  it("normalises a non-string rejection too", async () => {
    mockInvoke.mockRejectedValueOnce({ code: 42 });

    await expect(tauriInvoke("get_ca_info")).rejects.toThrow("[object Object]");
  });
});
