import { X402ExtensionUnapprovedError } from "./errors.js";

export const APPROVED_EXTENSION_HEADERS = [
  "X-402-Routing",
  "X-402-Limits",
  "X-402-Acceptable",
  "X-402-Metadata",
  "X-402-Security"
] as const;

export type ApprovedExtensionHeader = typeof APPROVED_EXTENSION_HEADERS[number];

export type X402Extension = {
  header: ApprovedExtensionHeader | string; // validate against approved list at runtime
  payload: Record<string, any>;
  // Additional metadata fields allowed and included in canonicalization
  [k: string]: any;
};

export function canonicalizeExtensionHeader(h: string): string {
  const found = (APPROVED_EXTENSION_HEADERS as readonly string[]).find(
    (ah) => ah.toLowerCase() === h.toLowerCase()
  );
  if (!found) throw new X402ExtensionUnapprovedError("X402_EXTENSION_UNAPPROVED");
  return found;
}

export const isApprovedExtensionHeader = (h: string) => {
  return (APPROVED_EXTENSION_HEADERS as readonly string[]).some(
    (ah) => ah.toLowerCase() === h.toLowerCase()
  );
};

export function setApprovedExtensionHeaders(headers: string[]) {
  // This is a bit of a hack for testing, but it works.
  (APPROVED_EXTENSION_HEADERS as unknown as string[]) = headers;
}

export type X402SecurityPayload = {
  jwksUrl?: string;        // JWKS endpoint URL
  jwks?: any;              // Inline JWKS
  // Minimal security requirements
  minKeyStrength?: number; // Minimum key size
  allowedSuites?: string[]; // Allowed cipher suites
};

