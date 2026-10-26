import { describe, it, expect, beforeEach, vi } from "vitest";
import { SCHEME_KEY } from "@wired-square/kit/core";

async function loadStore() {
  vi.resetModules();
  return import("../stores/theme");
}

const appliedScheme = () => document.documentElement.getAttribute("data-app-scheme");

describe("theme store", () => {
  beforeEach(() => localStorage.clear());

  it("follows the system when nothing was chosen", async () => {
    await loadStore();
    expect(appliedScheme()).toBe("light dark");
  });

  it("keeps a chosen scheme", async () => {
    localStorage.setItem(SCHEME_KEY, "dark");
    await loadStore();
    expect(appliedScheme()).toBe("dark");
  });

  it("carries a stored opca-theme over to the kit's key once", async () => {
    localStorage.setItem("opca-theme", "light");
    await loadStore();
    expect(appliedScheme()).toBe("light");
    expect(localStorage.getItem(SCHEME_KEY)).toBe("light");
    expect(localStorage.getItem("opca-theme")).toBeNull();
  });

  it("keeps a kit choice over a stale opca-theme", async () => {
    localStorage.setItem(SCHEME_KEY, "system");
    localStorage.setItem("opca-theme", "light");
    await loadStore();
    expect(appliedScheme()).toBe("light dark");
    expect(localStorage.getItem("opca-theme")).toBeNull();
  });
});
