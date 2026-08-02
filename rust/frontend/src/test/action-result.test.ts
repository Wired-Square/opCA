import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { renderHook } from "@solidjs/testing-library";
import { createActionResult } from "../utils/actionResult";

/** Mount the hook with a short timeout so the tests read clearly. Cleanup is
 * registered with the library's auto-afterEach, so a failed assertion cannot
 * leak a live timer into the next test. */
const mount = (ms = 1000) =>
  renderHook(createActionResult, { initialProps: [ms] }).result;

describe("createActionResult", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("starts empty", () => {
    expect(mount().result()).toBeNull();
  });

  it("auto-clears a success after the timeout", () => {
    const a = mount();
    a.report("Done");
    expect(a.result()).toEqual({ summary: "Done", error: null });

    vi.advanceTimersByTime(999);
    expect(a.result()).not.toBeNull();

    vi.advanceTimersByTime(1);
    expect(a.result()).toBeNull();
  });

  it("keeps a failure until it is cleared", () => {
    const a = mount();
    a.report("Upload failed", "boom");

    vi.advanceTimersByTime(60_000);
    expect(a.result()).toEqual({ summary: "Upload failed", error: "boom" });

    a.clear();
    expect(a.result()).toBeNull();
  });

  it("coerces a caught value to a string", () => {
    const a = mount();
    a.report("Failed", new Error("kaboom"));
    expect(a.result()?.error).toBe("Error: kaboom");
  });

  it("treats an omitted error as success", () => {
    const a = mount();
    a.report("Fine", undefined);
    expect(a.result()).toEqual({ summary: "Fine", error: null });
  });

  it("does not let an earlier success timer clear a later result", () => {
    const a = mount();
    a.report("First");
    vi.advanceTimersByTime(900);

    // The second report must cancel the first one's pending clear, otherwise
    // this failure would vanish 100ms later.
    a.report("Second failed", "boom");
    vi.advanceTimersByTime(60_000);

    expect(a.result()).toEqual({ summary: "Second failed", error: "boom" });
  });

  it("clear() cancels a pending success timer", () => {
    const a = mount();
    a.report("Done");
    a.clear();
    a.report("Later failure", "boom");

    vi.advanceTimersByTime(60_000);
    expect(a.result()).toEqual({ summary: "Later failure", error: "boom" });
  });

  it("cleans its timer up on unmount", () => {
    const clearSpy = vi.spyOn(globalThis, "clearTimeout");
    const { result: a, cleanup } = renderHook(createActionResult, { initialProps: [1000] });
    a.report("Done");
    cleanup();
    expect(clearSpy).toHaveBeenCalled();
    clearSpy.mockRestore();
  });
});
