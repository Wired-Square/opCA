import { describe, it, expect, vi } from "vitest";
import { Refusal } from "@wired-square/kit";
import { failureOf, headed } from "../utils/acting";

const failureFrom = (act: () => Promise<unknown>) => act().then(() => undefined, (e: unknown) => e);

describe("headed", () => {
  it("passes the result through", async () => {
    await expect(headed("Save failed", async () => 7)()).resolves.toBe(7);
  });

  it("leads a refusal's sentence with the headline", async () => {
    const e = await failureFrom(headed("Save failed", () => Promise.reject(new Refusal("vault locked"))));
    expect(e).toBeInstanceOf(Refusal);
    expect((e as Refusal).message).toBe("Save failed: vault locked");
  });

  it("keeps a plain error's text rather than the kit's generic sentence", async () => {
    const e = await failureFrom(headed("Save failed", () => Promise.reject(new Error("boom"))));
    expect((e as Refusal).message).toBe("Save failed: boom");
  });

  it("reads the headline after the body fails", async () => {
    // The Dashboard case: the generate landed, only the upload that followed
    // it failed, and the message has to say so.
    let generated = false;
    const e = await failureFrom(
      headed(
        () => (generated ? "Generated, but the upload failed" : "Generate failed"),
        async () => {
          generated = true;
          throw new Refusal("no route to host");
        },
      ),
    );
    expect((e as Refusal).message).toBe("Generated, but the upload failed: no route to host");
  });
});

describe("failureOf", () => {
  it("is nothing while a load has not failed", () => {
    expect(failureOf(undefined)).toBeUndefined();
  });

  it("is a refusal's own sentence", () => {
    expect(failureOf(new Refusal("vault not found"))).toBe("vault not found");
  });

  it("hides anything else behind the kit's sentence", () => {
    const quiet = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(failureOf(new Error("x is undefined"))).toBe("something went wrong in this page");
    quiet.mockRestore();
  });
});
