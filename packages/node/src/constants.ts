export const CanonicalHeaders = {
  X_PAYMENT: "X-PAYMENT",
  X_PAYMENT_RESPONSE: "X-PAYMENT-RESPONSE",
} as const;

export type HeaderEntry = { header: string; value: any };

export type TransportType =
  | "PAYMENT"
  | "PAYMENT_RESPONSE"
  | "PAYMENT_REQUIRED"
  | "OTHER_REQUEST"
  | "OTHER_RESPONSE";


