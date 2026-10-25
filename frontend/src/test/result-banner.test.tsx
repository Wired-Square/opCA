import { describe, it, expect, vi } from "vitest";
import { render, screen, renderHook } from "@solidjs/testing-library";
import { createAction } from "@wired-square/kit";
import ResultBanner, { ActionOutcome } from "../components/ResultBanner";
import { headed } from "../utils/acting";

const ok = { id: "abc123", ok: true, error: null };
const failed = { id: "def456", ok: false, error: "Storage error: bucket not found" };

describe("ResultBanner (bulk)", () => {
  it("reports counts neutrally when everything succeeded", () => {
    const { container } = render(() => (
      <ResultBanner results={[ok, { ...ok, id: "b" }]} onDismiss={() => {}} />
    ));
    expect(screen.getByText(/2 succeeded/)).toBeInTheDocument();
    // A bulk count is not an outcome to read as simply "good".
    expect(container.querySelector(".app-notice--neutral")).toBeInTheDocument();
    expect(container.querySelector('[role="alert"]')).toBeNull();
  });

  it("lists each failure against its identifier and alerts", () => {
    const { container } = render(() => (
      <ResultBanner results={[ok, failed]} onDismiss={() => {}} />
    ));
    expect(screen.getByText(/1 succeeded/)).toBeInTheDocument();
    expect(screen.getByText(/1 failed/)).toBeInTheDocument();
    expect(screen.getByText("def456")).toBeInTheDocument();
    expect(container.querySelector(".app-notice--bad")).toBeInTheDocument();
    expect(container.querySelector('[role="alert"]')).toBeInTheDocument();
  });

  it("dismisses on click", () => {
    const onDismiss = vi.fn();
    render(() => <ResultBanner results={[ok]} onDismiss={onDismiss} />);
    screen.getByText("Dismiss").click();
    expect(onDismiss).toHaveBeenCalledOnce();
  });
});

describe("ActionOutcome", () => {
  const mount = () => {
    const action = renderHook(createAction).result;
    const rendered = render(() => <ActionOutcome action={action} />);
    return { action, ...rendered };
  };

  it("renders nothing until the action reports", () => {
    const { container } = mount();
    expect(container.querySelector(".app-notice")).toBeNull();
  });

  it("shows a success as a good status", () => {
    const { action, container } = mount();
    action.succeed("CRL uploaded to public store");

    expect(screen.getByRole("status")).toHaveTextContent("CRL uploaded to public store");
    expect(container.querySelector(".app-notice--good")).toBeInTheDocument();
    expect(container.querySelector('[role="alert"]')).toBeNull();
  });

  it("alerts the headline beside the reason on failure", async () => {
    const { action } = mount();
    await action.run(headed("Upload failed", () => Promise.reject(new Error("bucket not found"))));

    // The headline must not be dropped — it names which action failed.
    expect(screen.getByRole("alert")).toHaveTextContent("Upload failed: bucket not found");
  });
});
