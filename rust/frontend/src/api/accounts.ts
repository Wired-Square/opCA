import { tauriInvoke } from "./tauri";
import type { AccountInfo } from "./types";

export async function listAccounts(): Promise<AccountInfo[]> {
  return tauriInvoke<AccountInfo[]>("list_accounts");
}

/**
 * What to put in the Account field when the user picks `account`.
 *
 * Purely about what `op --account` can resolve: it takes the sign-in address,
 * which is what an operator recognises, but rejects one shared by two
 * configured accounts — so only those fall back to the unambiguous UUID.
 * Which form ends up here no longer affects local settings; `settings.rs`
 * resolves all of them to one account (see its `account_key`).
 */
export function accountValue(account: AccountInfo, all: AccountInfo[]): string {
  const shared = all.filter((a) => a.url === account.url).length > 1;
  if (!shared) return account.url;
  return account.account_uuid || account.user_uuid || account.url;
}

/**
 * An Account field value as the user should read it: the account's email when
 * the value is one of the UUIDs above, so a disambiguated account doesn't show
 * up in the saved-logins list as a UUID.
 */
export function accountLabel(value: string | null, all: AccountInfo[]): string | null {
  if (!value) return value;
  const match = all.find((a) => a.account_uuid === value || a.user_uuid === value);
  return match ? match.email : value;
}
