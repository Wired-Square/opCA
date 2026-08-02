import { tauriInvoke } from "./tauri";
import type { AwsCredentialSelection, AwsItemRef } from "./types";

/** 1Password items in the connected account that could hold an AWS access key.
 * Item contents aren't read, so no secrets are fetched until one is chosen. */
export async function listAwsCredentials(): Promise<AwsItemRef[]> {
  return tauriInvoke<AwsItemRef[]>("list_aws_credentials");
}

export async function getAwsCredential(): Promise<AwsCredentialSelection> {
  return tauriInvoke<AwsCredentialSelection>("get_aws_credential");
}

/** Select (or with `null`, clear) this user's AWS credential for the connected
 * account. The backend validates the item before saving. */
export async function setAwsCredential(itemId: string | null): Promise<void> {
  return tauriInvoke<void>("set_aws_credential", { itemId });
}
