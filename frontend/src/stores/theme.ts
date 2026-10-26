import { createSignal, createEffect } from "solid-js";
import { SCHEME_KEY, applyTheme, chooseScheme, storedScheme } from "@wired-square/kit/core";
import { darkTheme, lightTheme } from "../styles/theme";

export type ThemeMode = "dark" | "light";

const LEGACY_KEY = "opca-theme";

export function initialThemeMode(): ThemeMode {
  try {
    const legacy = localStorage.getItem(LEGACY_KEY);
    if (legacy !== null) {
      if (localStorage.getItem(SCHEME_KEY) === null) localStorage.setItem(SCHEME_KEY, legacy);
      localStorage.removeItem(LEGACY_KEY);
    }
  } catch {
    // Storage blocked: nothing to carry over.
  }
  return storedScheme("dark") === "light" ? "light" : "dark";
}

applyTheme(lightTheme, darkTheme);

const [themeMode, setThemeMode] = createSignal<ThemeMode>(initialThemeMode());

createEffect(() => chooseScheme(themeMode()));

export function toggleTheme() {
  setThemeMode((prev) => (prev === "dark" ? "light" : "dark"));
}

export { themeMode, setThemeMode };
