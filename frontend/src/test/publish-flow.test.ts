import { describe, it, expect, vi } from "vitest";
import { renderHook } from "@solidjs/testing-library";
import { Refusal } from "@wired-square/kit";
import { createPublishFlow } from "../utils/publishFlow";

const mount = (upload: () => Promise<void>) =>
  renderHook(() => createPublishFlow({ upload, success: "Uploaded to store" })).result;

describe("createPublishFlow", () => {
  it("starts idle with no prompt", () => {
    const flow = mount(() => Promise.resolve());
    expect(flow.showPrompt()).toBe(false);
    expect(flow.pending()).toBe(false);
  });

  it("offer() raises the prompt and dismiss() clears it", () => {
    const flow = mount(() => Promise.resolve());
    flow.offer();
    expect(flow.showPrompt()).toBe(true);
    flow.dismiss();
    expect(flow.showPrompt()).toBe(false);
  });

  it("hides the prompt and reports the success sentence", async () => {
    const upload = vi.fn(() => Promise.resolve());
    const flow = mount(upload);
    flow.offer();

    await flow.handleUpload();

    expect(upload).toHaveBeenCalledOnce();
    expect(flow.showPrompt()).toBe(false);
    expect(flow.pending()).toBe(false);
    expect(flow.succeeded()).toBe("Uploaded to store");
  });

  it("leaves the prompt up and reports the failure", async () => {
    const flow = mount(() => Promise.reject(new Refusal("vault locked")));
    flow.offer();

    // Resolving rather than throwing is the contract Database relies on when
    // it chains a refetch after the upload.
    await expect(flow.handleUpload()).resolves.toBeUndefined();

    // The user should still be able to retry from the prompt.
    expect(flow.showPrompt()).toBe(true);
    expect(flow.pending()).toBe(false);
    expect(flow.failed()).toBe("Upload failed: vault locked");
  });

  it("is pending while the upload is in flight", async () => {
    let release!: () => void;
    const flow = mount(() => new Promise<void>((resolve) => { release = resolve; }));

    const done = flow.handleUpload();
    expect(flow.pending()).toBe(true);

    release();
    await done;
    expect(flow.pending()).toBe(false);
  });
});
