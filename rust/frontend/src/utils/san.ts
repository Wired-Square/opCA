/** Mirrors `SubjectAltName::from_str` in opca-core `services/san.rs`; the
 * backend re-validates, so the two must agree on what they accept. */

export type SanKind = "dns" | "ip4" | "ip6" | "email" | "uri";
export type SanCheck = { kind: SanKind } | { error: string };

export const SAN_KIND_LABEL: Record<SanKind, string> = {
  dns: "DNS name",
  ip4: "IPv4 address",
  ip6: "IPv6 address",
  email: "Email address",
  uri: "URI",
};

export const SAN_KIND_TAG: Record<SanKind, string> = {
  dns: "DNS",
  ip4: "IP",
  ip6: "IP",
  email: "Email",
  uri: "URI",
};

const DOTTED_QUAD = /^[0-9.]+$/;

function isIpv4(v: string): boolean {
  const parts = v.split(".");
  return parts.length === 4 && parts.every((p) => /^(0|[1-9][0-9]{0,2})$/.test(p) && Number(p) <= 255);
}

function isIpv6(v: string): boolean {
  if (!v.includes(":") || !/^[0-9a-fA-F:.]+$/.test(v)) return false;
  try {
    new URL(`http://[${v}]/`);
    return true;
  } catch {
    return false;
  }
}

function isDnsName(v: string, allowWildcard: boolean): boolean {
  const name = allowWildcard && v.startsWith("*.") ? v.slice(2) : v;
  const labels = name.split(".");
  return (
    name.length <= 253 &&
    !/^[0-9]+$/.test(labels[labels.length - 1]) &&
    labels.every((l) => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(l))
  );
}

function isUri(v: string): boolean {
  const scheme = v.indexOf("://");
  let rest: string;
  if (scheme >= 0) {
    if (!/^[A-Za-z][A-Za-z0-9+.-]*$/.test(v.slice(0, scheme))) return false;
    rest = v.slice(scheme + 3);
  } else if (/^urn:/i.test(v)) {
    rest = v.slice(4);
  } else {
    return false;
  }
  return rest.length > 0 && /^[\x21-\x7e]+$/.test(v);
}

export function classifySan(input: string): SanCheck {
  const v = input.trim();
  if (!v) return { error: "Enter a hostname, IP address, email or URI" };
  if (isIpv4(v)) return { kind: "ip4" };
  if (isIpv6(v)) return { kind: "ip6" };
  const at = v.indexOf("@");
  if (at >= 0) {
    const local = v.slice(0, at);
    if (!local || !/^[\x21-\x7e]+$/.test(local)) return { error: "Not a valid email address" };
    if (!isDnsName(v.slice(at + 1), false)) return { error: "Email domain is not a valid hostname" };
    return { kind: "email" };
  }
  if (isUri(v)) return { kind: "uri" };
  if (isDnsName(v, true)) return { kind: "dns" };
  if (DOTTED_QUAD.test(v)) return { error: "Not a valid IPv4 address" };
  return { error: "Not a valid hostname, IP address, email or URI" };
}
