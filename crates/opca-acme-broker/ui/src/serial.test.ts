import { describe, expect, it } from "vitest";

import { hexSerial } from "./serial";

describe("hexSerial", () => {
  it("prints a 127-bit random serial exactly, as openssl does", () => {
    expect(hexSerial("163789132247613422157751999876065005807")).toBe("7B38A3B2155DBAA3696F1DD32D1210EF");
  });

  it("pads to whole bytes", () => {
    expect(hexSerial("1")).toBe("01");
    expect(hexSerial("255")).toBe("FF");
    expect(hexSerial("256")).toBe("0100");
  });
});
