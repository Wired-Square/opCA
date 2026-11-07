const HIDDEN = "•".repeat(16);

/** The URI with its code hidden: whoever holds the code takes over the broker. */
export function masked(uri: string): string {
  const code = uri.lastIndexOf("code=");
  return code < 0 ? HIDDEN : `${uri.slice(0, code + "code=".length)}${HIDDEN}`;
}

export type PairingView =
  | { kind: "ask_an_admin" }
  | { kind: "offer" }
  | { kind: "issued"; uri: string; shown: string; revealed: boolean };

/** What an enrolling broker's page shows of pairing: only an admin issues a URI, and it starts masked. */
export function pairingView(admin: boolean, uri: string | null, revealed: boolean): PairingView {
  if (!admin) return { kind: "ask_an_admin" };
  if (uri === null) return { kind: "offer" };
  return { kind: "issued", uri, shown: revealed ? uri : masked(uri), revealed };
}
