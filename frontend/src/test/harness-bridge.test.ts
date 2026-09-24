import { describe as group, it, expect } from "vitest";
import { clippingAncestor, describe, rectInViewport } from "../harness/bridge";

function box(left: number, top: number, right: number, bottom: number) {
  return { left, top, right, bottom, x: left, y: top, width: right - left, height: bottom - top } as DOMRect;
}

function placed(el: HTMLElement, r: DOMRect) {
  el.getBoundingClientRect = () => r;
  return el;
}

group("rectInViewport", () => {
  it("accepts a rect inside, allowing sub-pixel overhang", () => {
    expect(rectInViewport(box(0, 0, 100, 50), 100, 50)).toBe(true);
    expect(rectInViewport(box(-0.3, 0, 100.3, 50), 100, 50)).toBe(true);
  });

  it("rejects a rect that spills over any edge", () => {
    expect(rectInViewport(box(-5, 0, 50, 50), 100, 100)).toBe(false);
    expect(rectInViewport(box(0, 60, 50, 120), 100, 100)).toBe(false);
  });
});

group("clippingAncestor", () => {
  function tree(scrollerRect: DOMRect, targetRect: DOMRect) {
    const scroller = placed(document.createElement("div"), scrollerRect);
    scroller.className = "table-wrap";
    scroller.style.overflow = "auto";
    const plain = placed(document.createElement("div"), box(0, 0, 10, 10));
    const target = placed(document.createElement("div"), targetRect);
    plain.appendChild(target);
    scroller.appendChild(plain);
    document.body.appendChild(scroller);
    return target;
  }

  it("names the overflow ancestor that cuts the element off", () => {
    const target = tree(box(0, 0, 200, 100), box(10, 80, 110, 140));
    expect(describe(clippingAncestor(target)!)).toBe("div.table-wrap");
  });

  it("is null when the overflow ancestor holds the element whole", () => {
    expect(clippingAncestor(tree(box(0, 0, 200, 200), box(10, 80, 110, 140)))).toBeNull();
  });

  it("ignores visible-overflow ancestors however small", () => {
    const outer = placed(document.createElement("div"), box(0, 0, 5, 5));
    const target = placed(document.createElement("span"), box(0, 0, 100, 100));
    outer.appendChild(target);
    document.body.appendChild(outer);
    expect(clippingAncestor(target)).toBeNull();
  });
});
