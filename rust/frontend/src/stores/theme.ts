import { createSignal, createEffect } from "solid-js";
import { darkTheme, lightTheme, applyTheme } from "../styles/theme";

export type ThemeMode = "dark" | "light";

const STORAGE_KEY = "opca-theme";

function getInitialTheme(): ThemeMode {
  if (typeof window !== "undefined") {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === "dark" || stored === "light") return stored;
  }
  return "dark"; // default to dark
}

const [themeMode, setThemeMode] = createSignal<ThemeMode>(getInitialTheme());

createEffect(() => {
  const mode = themeMode();
  applyTheme(mode === "dark" ? darkTheme : lightTheme);
  document.documentElement.setAttribute("data-theme", mode);
  localStorage.setItem(STORAGE_KEY, mode);
});

export function toggleTheme() {
  setThemeMode((prev) => (prev === "dark" ? "light" : "dark"));
}

export { themeMode, setThemeMode };
