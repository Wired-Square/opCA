import type { IssuedCertificate } from "./api";

export type Standing =
  | { kind: "valid" }
  | { kind: "expiring" }
  | { kind: "expired" }
  | { kind: "revoked"; reason: string };

/** RFC 5280's CRLReason codes; 7 is unused. */
const REASONS: Record<number, string> = {
  0: "unspecified",
  1: "key compromise",
  2: "CA compromise",
  3: "affiliation changed",
  4: "superseded",
  5: "cessation of operation",
  6: "certificate hold",
  8: "remove from CRL",
  9: "privilege withdrawn",
  10: "AA compromise",
};

export function reason(code: number | null): string {
  if (code === null) return REASONS[0];
  return REASONS[code] ?? `reason ${code}`;
}

/** Expiring in the last third of its lifetime, when ACME clients renew. */
export function standing(certificate: IssuedCertificate, now: number): Standing {
  if (certificate.revoked_at !== null) {
    return { kind: "revoked", reason: reason(certificate.revocation_reason) };
  }
  const from = Date.parse(certificate.not_before);
  const until = Date.parse(certificate.not_after);
  if (now >= until) return { kind: "expired" };
  if (now >= until - (until - from) / 3) return { kind: "expiring" };
  return { kind: "valid" };
}
