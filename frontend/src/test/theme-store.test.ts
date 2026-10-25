import { describe, it, expect, beforeEach } from "vitest";
import { SCHEME_KEY } from "@wired-square/kit/core";
import { initialThemeMode, setThemeMode, toggleTheme, themeMode } from "../stores/theme";

describe("theme store", () => {
  beforeEach(() => localStorage.clear());

  it("defaults to dark", () => {
    expect(initialThemeMode()).toBe("dark");
  });

  it("carries a stored opca-theme over to the kit's key once", () => {
    localStorage.setItem("opca-theme", "light");
    expect(initialThemeMode()).toBe("light");
    expect(localStorage.getItem(SCHEME_KEY)).toBe("light");
    expect(localStorage.getItem("opca-theme")).toBeNull();
  });

  it("keeps a kit choice over a stale opca-theme", () => {
    localStorage.setItem(SCHEME_KEY, "dark");
    localStorage.setItem("opca-theme", "light");
    expect(initialThemeMode()).toBe("dark");
    expect(localStorage.getItem("opca-theme")).toBeNull();
  });

  it("reads a system scheme as dark, since opca offers only dark and light", () => {
    localStorage.setItem(SCHEME_KEY, "system");
    expect(initialThemeMode()).toBe("dark");
  });

  it("sets data-app-scheme and keeps the choice", () => {
    setThemeMode("light");
    expect(document.documentElement.getAttribute("data-app-scheme")).toBe("light");
    expect(localStorage.getItem(SCHEME_KEY)).toBe("light");
    toggleTheme();
    expect(themeMode()).toBe("dark");
    expect(document.documentElement.getAttribute("data-app-scheme")).toBe("dark");
  });
});
