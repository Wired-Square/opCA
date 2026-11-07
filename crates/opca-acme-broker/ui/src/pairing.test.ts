import type { Role } from "@wired-square/appliance-types";
import { describe, expect, it } from "vitest";

import { masked, pairingView } from "./pairing";

const URI = "opca-acme://acme.home.example:9443#pin=0123abcd&code=ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const HIDDEN = "opca-acme://acme.home.example:9443#pin=0123abcd&code=••••••••••••••••";

describe("masked", () => {
  it("hides the code and keeps where it pairs", () => {
    expect(masked(URI)).toBe(HIDDEN);
  });

  it("hides the whole of anything without a code", () => {
    expect(masked("not a pairing URI")).toBe("••••••••••••••••");
  });
});

describe("pairingView", () => {
  const ADMIN: Record<Role, boolean> = { viewer: false, operator: false, admin: true, hostadmin: true };
  const admin = (role: Role) => ADMIN[role];

  it("offers viewers and operators no button, issued URI or not", () => {
    for (const role of ["viewer", "operator"] as const) {
      expect(pairingView(admin(role), null, false)).toEqual({ kind: "ask_an_admin" });
      expect(pairingView(admin(role), URI, true)).toEqual({ kind: "ask_an_admin" });
    }
  });

  it("offers admins the button, then the URI masked until revealed", () => {
    for (const role of ["admin", "hostadmin"] as const) {
      expect(pairingView(admin(role), null, false)).toEqual({ kind: "offer" });
      expect(pairingView(admin(role), URI, false)).toEqual({
        kind: "issued",
        uri: URI,
        shown: HIDDEN,
        revealed: false,
      });
      expect(pairingView(admin(role), URI, true)).toEqual({ kind: "issued", uri: URI, shown: URI, revealed: true });
    }
  });
});
