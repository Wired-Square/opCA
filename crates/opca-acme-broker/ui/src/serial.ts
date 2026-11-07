/** A decimal serial as `openssl x509 -serial` prints it: upper-case hex, whole bytes. */
export function hexSerial(decimal: string): string {
  const hex = BigInt(decimal).toString(16).toUpperCase();
  return hex.length % 2 ? `0${hex}` : hex;
}
