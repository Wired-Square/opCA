import { describe, it, expect } from "vitest";
import { render, screen } from "@solidjs/testing-library";
import Spinner from "../components/Spinner";

describe("Spinner", () => {
  it("renders without a message", () => {
    const { container } = render(() => <Spinner />);
    expect(container.querySelector(".spinner")).toBeInTheDocument();
    expect(container.textContent).toBe("");
  });

  it("renders with a message", () => {
    render(() => <Spinner message="Loading…" />);
    expect(screen.getByText("Loading…")).toBeInTheDocument();
  });

  it("applies the small variant class", () => {
    const { container } = render(() => <Spinner small />);
    expect(container.querySelector(".spinner-sm")).toBeInTheDocument();
  });

  it("passes extra class names through", () => {
    const { container } = render(() => <Spinner class="my-extra" />);
    const wrapper = container.querySelector(".loading-message");
    expect(wrapper?.className).toContain("my-extra");
  });
});
