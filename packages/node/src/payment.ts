export type XPaymentAuthorization = {
  from: string; // hex address
  to: string;   // hex address (resource server)
  value: string; // decimal string amount
  validAfter: string;  // unix seconds (string)
  validBefore: string; // unix seconds (string)
  nonce: string;       // hex
};

export type XPaymentPayload = {
  signature: string; // hex 0x...
  authorization: XPaymentAuthorization;
};

export type XPaymentHeader = {
  x402Version: 1;
  scheme: string; // e.g., "exact"
  network: string; // e.g., base, base-sepolia
  payload: XPaymentPayload;
};

export type XPaymentResponseHeader = {
  x402Version: 1;
  scheme: string; // e.g., "exact"
  network: string;
  payload: Record<string, any>; // opaque for now; integrity-protected in AAD
};

export type PaymentLike = XPaymentHeader | XPaymentResponseHeader;

export function isXPayment(obj: any): obj is XPaymentHeader {
  return obj && typeof obj === "object" && obj.payload && typeof obj.payload.signature === "string" && obj.authorization === undefined;
}

export function isXPaymentResponse(obj: any): obj is XPaymentResponseHeader {
  return obj && typeof obj === "object" && obj.payload && typeof obj.payload === "object" && obj.payload.signature === undefined;
}

export function normalizePaymentLike<T extends PaymentLike>(input: T): T {
  // Minimal structural checks; leave deep validation to integrators for now
  if (!input || typeof input !== "object") throw new Error("X_PAYMENT_SCHEMA");
  if (input.x402Version !== 1) throw new Error("X_PAYMENT_VERSION");
  if (!input.scheme || typeof input.scheme !== "string") throw new Error("X_PAYMENT_SCHEMA");
  if (!input.network || typeof input.network !== "string") throw new Error("X_PAYMENT_SCHEMA");
  if (!input.payload || typeof input.payload !== "object") throw new Error("X_PAYMENT_SCHEMA");
  return input;
}

function deepCanonicalize(obj: any): any {
  if (obj === null || typeof obj !== "object") return obj;
  if (Array.isArray(obj)) return obj.map(deepCanonicalize);
  const keys = Object.keys(obj).sort();
  const out: any = {};
  for (const k of keys) out[k] = deepCanonicalize(obj[k]);
  return out;
}

export function synthesizePaymentHeaderValue(p: PaymentLike): string {
  // Emit compact, stable JSON string (header value is JSON per x402 examples)
  return JSON.stringify(deepCanonicalize(p));
}

export function parsePaymentHeaderValue(s: string): PaymentLike | null {
  // Accept either raw JSON or base64-encoded JSON (be liberal in what we accept)
  try {
    const j = JSON.parse(s);
    return normalizePaymentLike(j);
  } catch (_) {
    try {
      const dec = Buffer.from(s, "base64").toString("utf8");
      const j2 = JSON.parse(dec);
      return normalizePaymentLike(j2);
    } catch {
      return null;
    }
  }
}

export function deriveExtendedAppFromPayment(p: XPaymentHeader): Record<string, string> {
  const a = p.payload.authorization;
  return {
    paymentScheme: String(p.scheme),
    paymentNetwork: String(p.network),
    paymentFrom: String(a.from),
    paymentTo: String(a.to),
    paymentValue: String(a.value),
    paymentValidAfter: String(a.validAfter),
    paymentValidBefore: String(a.validBefore),
    paymentNonce: String(a.nonce),
    paymentSignature: String(p.payload.signature),
  };
}
