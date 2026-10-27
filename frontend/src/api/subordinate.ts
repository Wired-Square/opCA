import { tauriInvoke, withLock } from "./tauri";
import type { SignSubordinateRequest, SignedSubordinate } from "./types";

export async function signSubordinate(
  request: SignSubordinateRequest,
): Promise<SignedSubordinate> {
  return withLock("sign_subordinate", () =>
    tauriInvoke<SignedSubordinate>("sign_subordinate", { request }),
  );
}
