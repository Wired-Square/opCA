import { describe, it, expect } from "vitest";
import { createSignal } from "solid-js";
import { render, screen } from "@solidjs/testing-library";
import { Badge } from "@wired-square/kit";

describe("kit", () => {
  it("shares opca's solid-js, so its components follow opca's signals", () => {
    const [tone, setTone] = createSignal<"good" | "bad">("good");
    render(() => <Badge tone={tone()}>state</Badge>);
    const badge = screen.getByText("state");
    expect(badge).toHaveClass("app-badge--good");
    setTone("bad");
    expect(badge).toHaveClass("app-badge--bad");
  });
});
