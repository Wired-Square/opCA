import { describe, it, expect } from "vitest";
import { placePopover } from "../utils/placePopover";

const viewport = { width: 1000, height: 800 };
const anchorAt = (top: number, left = 500, width = 28, height = 28) => ({
  top,
  bottom: top + height,
  left,
  right: left + width,
  width,
});
const start = { align: "start" as const, matchWidth: false };
const end = { align: "end" as const, matchWidth: false };

describe("placePopover", () => {
  it("opens below the anchor when it fits", () => {
    const p = placePopover(anchorAt(100), { width: 160, height: 120 }, viewport, start);
    expect(p.top).toBe(132);
    expect(p.maxHeight).toBe(800 - 128 - 4 - 8);
  });

  it("flips above the anchor near the bottom of the viewport", () => {
    const p = placePopover(anchorAt(740), { width: 160, height: 120 }, viewport, start);
    expect(p.top).toBe(740 - 4 - 120);
    expect(p.maxHeight).toBe(740 - 4 - 8);
  });

  it("caps its height on the roomier side when it fits neither", () => {
    const tall = { width: 160, height: 900 };
    const nearTop = placePopover(anchorAt(200), tall, viewport, start);
    expect(nearTop.top).toBe(232);
    expect(nearTop.maxHeight).toBe(800 - 228 - 12);

    const nearBottom = placePopover(anchorAt(600), tall, viewport, start);
    expect(nearBottom.maxHeight).toBe(600 - 12);
    expect(nearBottom.top).toBe(8);
  });

  it("right-aligns to the anchor with align end", () => {
    const p = placePopover(anchorAt(100, 500), { width: 160, height: 50 }, viewport, end);
    expect(p.left).toBe(528 - 160);
  });

  it("clamps to both viewport edges", () => {
    const size = { width: 160, height: 50 };
    expect(placePopover(anchorAt(100, 950), size, viewport, start).left).toBe(1000 - 8 - 160);
    expect(placePopover(anchorAt(100, 0), size, viewport, end).left).toBe(8);
  });

  it("takes the anchor's width with matchWidth", () => {
    const p = placePopover(anchorAt(100, 300, 240), { width: 160, height: 50 }, viewport, {
      align: "start",
      matchWidth: true,
    });
    expect(p.width).toBe(240);
    expect(p.left).toBe(300);
  });
});
