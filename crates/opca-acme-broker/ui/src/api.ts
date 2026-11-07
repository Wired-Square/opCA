import { Refusal } from "@wired-square/kit/core";

export type AppState = "needs_host" | "enrolling" | "enrolled" | "paused" | "revoked";

export interface AppStatus {
  state: AppState;
  host: string | null;
  api_url: string | null;
  acme_directory: string | null;
  ca_url: string | null;
  crl_url: string | null;
  /** The CRL being published, while one is. */
  crl: { number: number | null; this_update: string; next_update: string | null } | null;
  domains: string[];
  subordinate: { serial: string; not_after: string } | null;
}

export interface IssuedCertificate {
  serial: string;
  common_name: string | null;
  sans: string[];
  not_before: string;
  not_after: string;
  issuer_serial: string;
  revoked_at: string | null;
  revocation_reason: number | null;
  changed: number;
}

export interface IssuedNewest {
  certificates: IssuedCertificate[];
  before: number | null;
}

/** `true` for the revoked alone, `false` for the rest, `null` for every one. */
export type RevokedFilter = boolean | null;

/** `path` is relative, so it resolves against the `<base href>` the broker serves. */
async function ask<T>(path: string, method = "GET"): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, { method, headers: { accept: "application/json" } });
  } catch {
    throw new Refusal("the broker didn't answer", { unanswered: true });
  }
  if (!response.ok) {
    const body = await response.text();
    let message = body;
    try {
      message = JSON.parse(body).message ?? body;
    } catch {}
    throw new Refusal(message || `the broker answered ${response.status}`);
  }
  return response.json();
}

export const status = () => ask<AppStatus>("api/status");

/** Admins only: a new pairing code's URI, which spends the code before it. */
export const newPairing = () => ask<{ uri: string }>("api/pairing", "POST");

export function issued(revoked: RevokedFilter, before: number | null): Promise<IssuedNewest> {
  const query = new URLSearchParams();
  if (before !== null) query.set("before", String(before));
  if (revoked !== null) query.set("revoked", String(revoked));
  const asked = String(query);
  return ask<IssuedNewest>(asked ? `api/issued?${asked}` : "api/issued");
}
