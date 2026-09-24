export interface AnchorRect {
  top: number;
  bottom: number;
  left: number;
  right: number;
  width: number;
}

export interface Size {
  width: number;
  height: number;
}

export interface PlaceOptions {
  align: "start" | "end";
  matchWidth: boolean;
}

export interface Placement {
  top: number;
  left: number;
  maxHeight: number;
  width?: number;
}

const GAP = 4;
const MARGIN = 8;

/** Opens below the anchor if it fits, else above if it fits there, else on the
 *  roomier side with its height capped; always kept inside the viewport. */
export function placePopover(
  anchor: AnchorRect,
  size: Size,
  viewport: Size,
  { align, matchWidth }: PlaceOptions,
): Placement {
  const below = viewport.height - anchor.bottom - GAP - MARGIN;
  const above = anchor.top - GAP - MARGIN;
  const opensBelow = size.height <= below || (size.height > above && below >= above);
  const maxHeight = opensBelow ? below : above;
  const top = opensBelow
    ? anchor.bottom + GAP
    : anchor.top - GAP - Math.min(size.height, maxHeight);

  const width = matchWidth ? anchor.width : size.width;
  const preferred = align === "end" ? anchor.right - width : anchor.left;
  const left = Math.max(MARGIN, Math.min(preferred, viewport.width - MARGIN - width));

  return { top, left, maxHeight, width: matchWidth ? width : undefined };
}
