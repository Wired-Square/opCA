import { describe, it, expect } from "vitest";
import { accountValue, accountLabel } from "../api/accounts";
import type { AccountInfo } from "../api/types";

const account = (over: Partial<AccountInfo>): AccountInfo => ({
  url: "example.1password.com",
  email: "someone@example.com",
  account_uuid: "ACCT",
  user_uuid: "USER",
  ...over,
});

const wired = account({ url: "wiredsquare.1password.com", email: "alex@wiredsquare.com", account_uuid: "W-ACCT", user_uuid: "W-USER" });
// Two personal accounts at the same sign-in address — `op --account` cannot
// tell them apart from the address alone.
const personalA = account({ url: "my.1password.com", email: "alex@wiredsquare.com", account_uuid: "A-ACCT", user_uuid: "A-USER" });
const personalB = account({ url: "my.1password.com", email: "alex@ferrara.com.au", account_uuid: "B-ACCT", user_uuid: "B-USER" });

const all = [wired, personalA, personalB];

describe("accountValue", () => {
  it("uses the sign-in address when it identifies one account", () => {
    expect(accountValue(wired, all)).toBe("wiredsquare.1password.com");
  });

  it("falls back to the account UUID when two accounts share an address", () => {
    expect(accountValue(personalA, all)).toBe("A-ACCT");
    expect(accountValue(personalB, all)).toBe("B-ACCT");
  });

  it("falls back to the user UUID when the account UUID is missing", () => {
    const noAcct = { ...personalA, account_uuid: "" };
    expect(accountValue(noAcct, [noAcct, personalB])).toBe("A-USER");
  });

  it("keeps the address when neither UUID is available", () => {
    const bare = { ...personalA, account_uuid: "", user_uuid: "" };
    expect(accountValue(bare, [bare, personalB])).toBe("my.1password.com");
  });
});

describe("accountLabel", () => {
  it("resolves a UUID back to the account's email", () => {
    expect(accountLabel("A-ACCT", all)).toBe("alex@wiredsquare.com");
    expect(accountLabel("B-USER", all)).toBe("alex@ferrara.com.au");
  });

  it("passes an address through unchanged", () => {
    expect(accountLabel("wiredsquare.1password.com", all)).toBe("wiredsquare.1password.com");
  });

  it("passes an unrecognised value through, so a stale saved login still reads", () => {
    expect(accountLabel("gone.1password.com", all)).toBe("gone.1password.com");
    expect(accountLabel("UNKNOWN-UUID", [])).toBe("UNKNOWN-UUID");
  });

  it("leaves an absent account absent", () => {
    expect(accountLabel(null, all)).toBeNull();
    expect(accountLabel("", all)).toBe("");
  });
});
