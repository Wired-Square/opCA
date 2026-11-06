import { describe, expect, it } from "vitest";

import type { IssuedCertificate } from "./api";
import { reason, standing } from "./standing";

const DAY = 86_400_000;
const FROM = Date.parse("2026-01-01T00:00:00Z");

function issuedFor(days: number, revoked?: { reason: number | null }): IssuedCertificate {
  return {
    serial: "1",
    common_name: "host.home.example",
    sans: ["host.home.example"],
    not_before: new Date(FROM).toISOString(),
    not_after: new Date(FROM + days * DAY).toISOString(),
    issuer_serial: "9",
    revoked_at: revoked ? new Date(FROM + DAY).toISOString() : null,
    revocation_reason: revoked?.reason ?? null,
    changed: 1,
  };
}

describe("standing", () => {
  it("is valid until the last third of its lifetime, expiring through it, then expired", () => {
    const ninety = issuedFor(90);
    expect(standing(ninety, FROM)).toEqual({ kind: "valid" });
    expect(standing(ninety, FROM + 59 * DAY)).toEqual({ kind: "valid" });
    expect(standing(ninety, FROM + 60 * DAY)).toEqual({ kind: "expiring" });
    expect(standing(ninety, FROM + 90 * DAY - 1)).toEqual({ kind: "expiring" });
    expect(standing(ninety, FROM + 90 * DAY)).toEqual({ kind: "expired" });
  });

  it("scales the window to a short lifetime", () => {
    const week = issuedFor(6);
    expect(standing(week, FROM + 3 * DAY)).toEqual({ kind: "valid" });
    expect(standing(week, FROM + 4 * DAY)).toEqual({ kind: "expiring" });
  });

  it("is revoked with its reason before anything its dates say", () => {
    expect(standing(issuedFor(90, { reason: 1 }), FROM + 2 * DAY)).toEqual({
      kind: "revoked",
      reason: "key compromise",
    });
    expect(standing(issuedFor(90, { reason: null }), FROM + 200 * DAY)).toEqual({
      kind: "revoked",
      reason: "unspecified",
    });
  });
});

describe("reason", () => {
  it("names RFC 5280's codes and numbers any other", () => {
    expect(reason(4)).toBe("superseded");
    expect(reason(10)).toBe("AA compromise");
    expect(reason(7)).toBe("reason 7");
  });
});
