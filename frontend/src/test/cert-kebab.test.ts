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
