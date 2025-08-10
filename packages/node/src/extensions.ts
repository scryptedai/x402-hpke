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

export function isApprovedExtensionHeader(header: string): header is ApprovedExtensionHeader {
  return APPROVED_EXTENSION_HEADERS.some((h) => h.toLowerCase() === String(header).toLowerCase());
}

export function canonicalizeExtensionHeader(header: string): ApprovedExtensionHeader {
  const found = APPROVED_EXTENSION_HEADERS.find((h) => h.toLowerCase() === String(header).toLowerCase());
  if (!found) throw new X402ExtensionUnapprovedError("X402_EXTENSION_UNAPPROVED");
  return found;
}

export type X402SecurityPayload = {
  jwksUrl?: string;        // JWKS endpoint URL
  jwks?: any;              // Inline JWKS
  // Minimal security requirements
  minKeyStrength?: number; // Minimum key size
  allowedSuites?: string[]; // Allowed cipher suites
};

