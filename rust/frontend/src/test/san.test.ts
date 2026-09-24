import { describe, it, expect } from "vitest";
import { classifySan } from "../utils/san";

describe("classifySan", () => {
  it.each([
    ["www.example.com", "dns"],
    ["*.example.com", "dns"],
    ["localhost", "dns"],
    ["10.0.0.5", "ip4"],
    ["2001:db8::1", "ip6"],
    ["::1", "ip6"],
    ["ops@example.com", "email"],
    ["spiffe://prod/web", "uri"],
    ["https://example.com/id", "uri"],
    ["urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66", "uri"],
  ])("accepts %s as %s", (input, kind) => {
    expect(classifySan(input)).toEqual({ kind });
  });

  // The same rejections as the Rust `rejects_invalid_input` table.
  it.each([
    "", "   ", "10.0.0.300", "1.2.3", "010.0.0.1", "a@b@c", "@example.com", "user@bad_domain",
    "user@*.example.com", "-bad.example.com", "bad-.example.com", "foo..com",
    "no-scheme/path", "example.com:443", "https://", "has space.com", "*.*.example.com",
    "www.*.example.com", "::1]/x[",
  ])("rejects %j", (input) => {
    expect(classifySan(input)).toHaveProperty("error");
  });

  it("names a bad dotted quad as an IPv4 mistake", () => {
    expect(classifySan("10.0.0.300")).toEqual({ error: "Not a valid IPv4 address" });
  });

  it("says when only the email domain is wrong", () => {
    expect(classifySan("ops@bad_domain")).toEqual({ error: "Email domain is not a valid hostname" });
  });
});
