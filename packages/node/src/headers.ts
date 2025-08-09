import type { X402Fields } from "./aad.js";

export function buildX402Headers(x: X402Fields): Record<string, string> {
  return {
    "X-X402-Invoice-Id": x.invoiceId,
    "X-X402-Chain-Id": String(x.chainId),
    "X-X402-Token-Contract": x.tokenContract,
    "X-X402-Amount": x.amount,
    "X-X402-Recipient": x.recipient,
    "X-X402-Tx-Hash": x.txHash,
    "X-X402-Expiry": String(x.expiry),
    "X-X402-Price-Hash": x.priceHash,
  };
}