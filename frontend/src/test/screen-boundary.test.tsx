import { describe, it, expect, vi } from "vitest";
import { createSignal, type ParentProps } from "solid-js";
import { MemoryRouter, Route, useNavigate } from "@solidjs/router";
import { render, screen } from "@solidjs/testing-library";
import { Refusal, ScreenBoundary } from "@wired-square/kit";

/** Throws while `broken` is true, so a test can heal it before a retry. */
function Boom(props: { broken: () => boolean }) {
  if (props.broken()) throw new Refusal("resource exploded");
  return <p>page content</p>;
}

/**
 * Mirrors App.tsx: ONE boundary in the router root, wrapping the outlet — so
 * the same boundary instance survives route changes, which is the whole point
 * of the reset. Putting a boundary inside each route would pass trivially.
 */
function mount(broken: () => boolean) {
  let navigate!: (to: string) => void;

  const Root = (props: ParentProps) => {
    navigate = useNavigate();
    return <ScreenBoundary>{props.children}</ScreenBoundary>;
  };

  const rendered = render(() => (
    <MemoryRouter root={Root}>
      <Route path="/" component={() => <Boom broken={broken} />} />
      <Route path="/other" component={() => <p>other page</p>} />
    </MemoryRouter>
  ));

  return { ...rendered, go: (to: string) => navigate(to) };
}

describe("ScreenBoundary around the outlet", () => {
  it("renders children when nothing throws", () => {
    mount(() => false);
    expect(screen.getByText("page content")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("shows the refusal in place of the page", () => {
    mount(() => true);
    expect(screen.getByRole("alert")).toHaveTextContent("resource exploded");
  });

  it("Try again re-renders, recovering once the cause is fixed", async () => {
    const [broken, setBroken] = createSignal(true);
    mount(broken);

    setBroken(false);
    screen.getByText("Try again").click();

    await vi.waitFor(() => expect(screen.getByText("page content")).toBeInTheDocument());
  });

  it("recovers on its own when the user navigates away", async () => {
    // Solid's ErrorBoundary latches on `errored()`, so this is worth pinning:
    // the router rebuilds the outlet, which clears the failure without the
    // boundary's `pathname`.
    const { go } = mount(() => true);
    expect(screen.getByRole("alert")).toBeInTheDocument();

    go("/other");

    await vi.waitFor(() => expect(screen.getByText("other page")).toBeInTheDocument());
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
