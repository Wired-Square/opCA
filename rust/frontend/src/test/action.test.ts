import { describe, it, expect, vi } from "vitest";
import { renderHook } from "@solidjs/testing-library";
import { createActionResult } from "../utils/actionResult";
import { createAction } from "../utils/action";

function mount() {
  return renderHook(() => {
    const outcome = createActionResult();
    return { outcome, action: createAction(outcome) };
  }).result;
}

describe("createAction", () => {
  it("starts idle with no result", () => {
    const { action, outcome } = mount();
    expect(action.busy()).toBe(false);
    expect(outcome.result()).toBeNull();
  });

  it("reports the success summary once the body resolves", async () => {
    const { action, outcome } = mount();
    const fn = vi.fn(() => Promise.resolve());

    await action.run({ success: "Saved", failure: "Save failed" }, fn);

    expect(fn).toHaveBeenCalledOnce();
    expect(outcome.result()).toEqual({ summary: "Saved", error: null });
  });

  it("stays silent on success when no summary is given", async () => {
    // Rekey and renew navigate away; the destination reports for itself.
    const { action, outcome } = mount();
    await action.run({ failure: "Rekey failed" }, () => Promise.resolve());
    expect(outcome.result()).toBeNull();
  });

  it("reports the failure with the coerced error", async () => {
    const { action, outcome } = mount();

    // Resolving rather than throwing is what lets the caller put its old
    // `finally` tail on the line after the await.
    await expect(
      action.run({ success: "Saved", failure: "Save failed" }, () => Promise.reject("vault locked")),
    ).resolves.toBeUndefined();

    expect(outcome.result()).toEqual({ summary: "Save failed", error: "vault locked" });
  });

  it("coerces a thrown Error for display", async () => {
    const { action, outcome } = mount();
    await action.run({ failure: "Save failed" }, () => Promise.reject(new Error("boom")));
    expect(outcome.result()?.error).toBe("Error: boom");
  });

  it("builds the success summary from what the body returned", async () => {
    const { action, outcome } = mount();

    await action.run(
      { success: (crl) => `CRL #${crl.number} generated`, failure: "Generate failed" },
      async () => ({ number: 7 }),
    );

    expect(outcome.result()?.summary).toBe("CRL #7 generated");
  });

  it("resolves the failure message after the body too", async () => {
    // The Dashboard case: the generate landed, only the upload that followed
    // it failed, and the message has to say so.
    const { action, outcome } = mount();
    let generated = false;

    await action.run({ failure: () => (generated ? "Generated, but the upload failed" : "Generate failed") },
      async () => { generated = true; throw new Error("no route to host"); });

    expect(outcome.result()?.summary).toBe("Generated, but the upload failed");
  });

  it("is busy while in flight and idle after, either way", async () => {
    const { action } = mount();
    let release!: () => void;

    const done = action.run(
      { failure: "Failed" },
      () => new Promise<void>((resolve) => { release = resolve; }),
    );
    expect(action.busy()).toBe(true);

    release();
    await done;
    expect(action.busy()).toBe(false);

    await action.run({ failure: "Failed" }, () => Promise.reject("nope"));
    expect(action.busy()).toBe(false);
  });

  it("clears the previous result before running again", async () => {
    const { action, outcome } = mount();
    await action.run({ success: "Saved", failure: "Save failed" }, () => Promise.resolve());

    let seen: unknown = "unset";
    await action.run({ failure: "Save failed" }, async () => { seen = outcome.result(); });

    expect(seen).toBeNull();
  });
});
