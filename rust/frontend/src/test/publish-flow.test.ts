import { describe, it, expect, vi } from "vitest";
import { renderHook } from "@solidjs/testing-library";
import { createActionResult } from "../utils/actionResult";
import { createPublishFlow } from "../utils/publishFlow";

function mount(upload: () => Promise<void>) {
  return renderHook(() => {
    const outcome = createActionResult();
    const flow = createPublishFlow({ upload, success: "Uploaded to store", outcome });
    return { outcome, flow };
  }).result;
}

describe("createPublishFlow", () => {
  it("starts idle with no prompt", () => {
    const { flow } = mount(() => Promise.resolve());
    expect(flow.showPrompt()).toBe(false);
    expect(flow.uploading()).toBe(false);
  });

  it("offer() raises the prompt and dismiss() clears it", () => {
    const { flow } = mount(() => Promise.resolve());
    flow.offer();
    expect(flow.showPrompt()).toBe(true);
    flow.dismiss();
    expect(flow.showPrompt()).toBe(false);
  });

  it("hides the prompt and reports the success summary", async () => {
    const upload = vi.fn(() => Promise.resolve());
    const { flow, outcome } = mount(upload);
    flow.offer();

    await flow.handleUpload();

    expect(upload).toHaveBeenCalledOnce();
    expect(flow.showPrompt()).toBe(false);
    expect(flow.uploading()).toBe(false);
    expect(outcome.result()).toEqual({ summary: "Uploaded to store", error: null });
  });

  it("leaves the prompt up and reports the failure", async () => {
    const { flow, outcome } = mount(() => Promise.reject("vault locked"));
    flow.offer();

    // Resolving rather than throwing is the contract Database relies on when
    // it chains a refetch after the upload.
    await expect(flow.handleUpload()).resolves.toBeUndefined();

    // The user should still be able to retry from the prompt.
    expect(flow.showPrompt()).toBe(true);
    expect(flow.uploading()).toBe(false);
    expect(outcome.result()).toEqual({ summary: "Upload failed", error: "vault locked" });
  });

  it("coerces a thrown Error for display", async () => {
    const { flow, outcome } = mount(() => Promise.reject(new Error("boom")));
    await flow.handleUpload();
    expect(outcome.result()?.error).toBe("Error: boom");
  });

  it("reports uploading while in flight", async () => {
    let release!: () => void;
    const { flow } = mount(() => new Promise<void>((resolve) => { release = resolve; }));

    const done = flow.handleUpload();
    expect(flow.uploading()).toBe(true);

    release();
    await done;
    expect(flow.uploading()).toBe(false);
  });
});
