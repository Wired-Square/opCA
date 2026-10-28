import { describe, it, expect } from "vitest";
import { darkTheme, lightTheme } from "../styles/theme";

describe.each([
  ["light", lightTheme],
  ["dark", darkTheme],
])("%s theme", (_, theme) => {
  it("stripes rows apart from both the page and a dialog", () => {
    expect(theme["--bg-stripe"]).not.toBe(theme["--app-bg"]);
    expect(theme["--bg-stripe"]).not.toBe(theme["--app-surface"]);
  });
});
