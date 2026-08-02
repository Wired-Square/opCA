import { describe, it, expect, vi } from "vitest";
import { render, screen, renderHook } from "@solidjs/testing-library";
import ResultBanner, { ActionResultBanner, ActionResultLine } from "../components/ResultBanner";
import { createActionResult } from "../utils/actionResult";

const ok = { id: "abc123", ok: true, error: null };
const failed = { id: "def456", ok: false, error: "Storage error: bucket not found" };

describe("ResultBanner (bulk)", () => {
  it("reports counts neutrally when everything succeeded", () => {
    const { container } = render(() => (
      <ResultBanner results={[ok, { ...ok, id: "b" }]} onDismiss={() => {}} />
    ));
    expect(screen.getByText(/2 succeeded/)).toBeInTheDocument();
    // A bulk count is not an outcome to read as simply "good".
    expect(container.querySelector(".result-banner-success")).toBeNull();
    expect(container.querySelector('[role="alert"]')).toBeNull();
  });

  it("lists each failure against its identifier and alerts", () => {
    const { container } = render(() => (
      <ResultBanner results={[ok, failed]} onDismiss={() => {}} />
    ));
    expect(screen.getByText(/1 succeeded/)).toBeInTheDocument();
    expect(screen.getByText(/1 failed/)).toBeInTheDocument();
    expect(screen.getByText("def456")).toBeInTheDocument();
    expect(container.querySelector(".result-banner-error")).toBeInTheDocument();
    expect(container.querySelector('[role="alert"]')).toBeInTheDocument();
  });

  it("dismisses on click", () => {
    const onDismiss = vi.fn();
    render(() => <ResultBanner results={[ok]} onDismiss={onDismiss} />);
    screen.getByText("Dismiss").click();
    expect(onDismiss).toHaveBeenCalledOnce();
  });
});

describe("ActionResultBanner (single action)", () => {
  const mount = () => {
    const outcome = renderHook(createActionResult).result;
    const rendered = render(() => <ActionResultBanner outcome={outcome} />);
    return { outcome, ...rendered };
  };

  it("renders nothing until something is reported", () => {
    const { container } = mount();
    expect(container.querySelector(".result-banner")).toBeNull();
  });

  it("shows a success in the green variant with no failure list", () => {
    const { outcome, container } = mount();
    outcome.report("CRL uploaded to public store");

    expect(screen.getByText("CRL uploaded to public store")).toBeInTheDocument();
    expect(container.querySelector(".result-banner-success")).toBeInTheDocument();
    expect(container.querySelector(".failure-list")).toBeNull();
    expect(container.querySelector('[role="alert"]')).toBeNull();
  });

  it("shows the summary and the error, and alerts, on failure", () => {
    const { outcome, container } = mount();
    outcome.report("Upload failed", "Storage error: bucket not found");

    expect(screen.getByText("Upload failed")).toBeInTheDocument();
    expect(screen.getByText("Storage error: bucket not found")).toBeInTheDocument();
    expect(container.querySelector(".result-banner-error")).toBeInTheDocument();
    expect(container.querySelector('[role="alert"]')).toBeInTheDocument();
  });

  it("Dismiss clears the underlying result", () => {
    const { outcome, container } = mount();
    outcome.report("Upload failed", "boom");
    screen.getByText("Dismiss").click();

    expect(outcome.result()).toBeNull();
    expect(container.querySelector(".result-banner")).toBeNull();
  });
});

describe("ActionResultLine (inline variant)", () => {
  const mount = () => {
    const outcome = renderHook(createActionResult).result;
    const rendered = render(() => <ActionResultLine outcome={outcome} />);
    return { outcome, ...rendered };
  };

  it("shows the summary alone on success", () => {
    const { outcome, container } = mount();
    outcome.report("Configuration saved.");
    expect(container.querySelector(".form-success")?.textContent).toBe("Configuration saved.");
  });

  it("keeps the summary alongside the error on failure", () => {
    const { outcome, container } = mount();
    outcome.report("Save failed", "vault locked");
    // The summary must not be dropped — it names which action failed.
    expect(container.querySelector(".form-error")?.textContent).toBe("Save failed: vault locked");
    expect(container.querySelector('[role="alert"]')).toBeInTheDocument();
  });
});
