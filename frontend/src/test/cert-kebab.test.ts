import { describe, it, expect } from "vitest";
import { certKebabItems } from "../api/certActions";
import type { CertListItem } from "../api/types";

const noop = () => {};
const handlers = { onRekey: noop, onRenew: noop, onRevoke: noop, onDelete: noop, onIgnore: noop, onUnignore: noop };
const labels = (cert: Partial<CertListItem>) =>
  certKebabItems(cert as CertListItem, handlers).map((i) => i.label);

describe("certKebabItems delete gating", () => {
  it("offers Delete on revoked and expired certificates", () => {
    expect(labels({ status: "Revoked", cert_type: "webserver" })).toContain("Delete");
    expect(labels({ status: "Expired", cert_type: "device" })).toContain("Delete");
  });

  it("withholds Delete from valid certificates and the CA", () => {
    expect(labels({ status: "Valid", cert_type: "webserver" })).not.toContain("Delete");
    expect(labels({ status: "Expired", cert_type: "ca" })).not.toContain("Delete");
  });
});

describe("certKebabItems publish gating", () => {
  const publishable = (cert: Partial<CertListItem>) =>
    certKebabItems(cert as CertListItem, { ...handlers, onPublish: noop }).some((i) => i.label === "Publish");

  it("offers Publish on a valid leaf with a CN", () => {
    expect(publishable({ status: "Valid", cert_type: "webserver", cn: "www.example.com" })).toBe(true);
  });

  it("withholds Publish from revoked, expired, CA and subordinate certs, and one with no CN", () => {
    expect(publishable({ status: "Revoked", cert_type: "webserver", cn: "a.example.com" })).toBe(false);
    expect(publishable({ status: "Expired", cert_type: "webserver", cn: "a.example.com" })).toBe(false);
    expect(publishable({ status: "Valid", cert_type: "ca", cn: "Test CA" })).toBe(false);
    expect(publishable({ status: "Valid", cert_type: "subordinateca", cn: "Broker CA" })).toBe(false);
    expect(publishable({ status: "Valid", cert_type: "webserver", cn: null })).toBe(false);
  });

  it("leaves Publish out where no handler is given", () => {
    expect(labels({ status: "Valid", cert_type: "webserver", cn: "www.example.com" })).not.toContain("Publish");
  });
});
