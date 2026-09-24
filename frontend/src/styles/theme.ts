export const darkTheme = {
  "--bg-primary": "#131316",
  "--bg-surface": "#1A1A1E",
  "--bg-elevated": "#232328",
  "--bg-hover": "#2A2A30",
  "--border": "#2E2E33",
  "--border-light": "#3A3A40",
  "--text-primary": "#F5F5F7",
  "--text-secondary": "#A1A1A6",
  "--text-tertiary": "#6E6E73",
  "--accent": "#F37021",
  "--accent-hover": "#FF8C42",
  "--accent-active": "#D45A0A",
  "--accent-glow": "rgba(243, 112, 33, 0.12)",
  "--accent-glow-strong": "rgba(243, 112, 33, 0.24)",
  "--success": "#30D158",
  "--warning": "#FFD60A",
  "--error": "#FF453A",
  "--info": "#64D2FF",
  "--caution": "#FF9500",
  "--link": "#3B82F6",
  "--neutral": "#8A8A91",
  "--on-accent": "#FFFFFF",
} as const;

export const lightTheme = {
  "--bg-primary": "#FFFFFF",
  "--bg-surface": "#F5F5F7",
  "--bg-elevated": "#FFFFFF",
  "--bg-hover": "#E8E8ED",
  "--border": "#D2D2D7",
  "--border-light": "#E8E8ED",
  "--text-primary": "#1D1D1F",
  "--text-secondary": "#6E6E73",
  "--text-tertiary": "#86868B",
  "--accent": "#F37021",
  "--accent-hover": "#D45A0A",
  "--accent-active": "#B84A08",
  "--accent-glow": "rgba(243, 112, 33, 0.08)",
  "--accent-glow-strong": "rgba(243, 112, 33, 0.16)",
  "--success": "#248A3D",
  "--warning": "#B25000",
  "--error": "#D70015",
  "--info": "#0071E3",
  "--caution": "#FF9500",
  "--link": "#3B82F6",
  "--neutral": "#8A8A91",
  "--on-accent": "#FFFFFF",
} as const;

export type Theme = Record<string, string>;

export function applyTheme(theme: Theme) {
  const root = document.documentElement;
  for (const [property, value] of Object.entries(theme)) {
    root.style.setProperty(property, value);
  }
}
