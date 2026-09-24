import { describe, it, expect } from "vitest";
import { render, screen } from "@solidjs/testing-library";
import PageError from "../components/PageError";

describe("PageError", () => {
  it("announces the message to assistive tech", () => {
    render(() => <PageError message="Vault not found" />);
    const el = screen.getByRole("alert");
    expect(el).toHaveTextContent("Vault not found");
    expect(el.className).toContain("page-error");
  });

  it("coerces a thrown value, so a caught error can be passed straight in", () => {
    render(() => <PageError message={new Error("boom")} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Error: boom");
  });

  it("renders nothing for an empty message", () => {
    const { container } = render(() => <PageError message="" />);
    expect(container).toBeEmptyDOMElement();
  });

  it("takes the form spacing when placed under a form", () => {
    render(() => <PageError message="x" placement="form" />);
    expect(screen.getByRole("alert")).toHaveClass("page-error", "page-error--form");
  });

  it("passes extra class names through", () => {
    const { container } = render(() => <PageError message="x" class="mt-3" />);
    expect(container.querySelector(".page-error")?.className).toContain("mt-3");
  });
});
