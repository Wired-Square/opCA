import { SCHEME_KEY, applyScheme, applyTheme, storedScheme } from "@wired-square/kit/core";
import { darkTheme, lightTheme } from "../styles/theme";

const LEGACY_KEY = "opca-theme";

export function carryOverLegacyTheme() {
  try {
    const legacy = localStorage.getItem(LEGACY_KEY);
    if (legacy !== null) {
      if (localStorage.getItem(SCHEME_KEY) === null) localStorage.setItem(SCHEME_KEY, legacy);
      localStorage.removeItem(LEGACY_KEY);
    }
  } catch {
    // Storage blocked: nothing to carry over.
  }
}

carryOverLegacyTheme();
applyTheme(lightTheme, darkTheme);
applyScheme(storedScheme("system"));
