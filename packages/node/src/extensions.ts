import { X402ExtensionUnapprovedError } from "./errors.js";

export let APPROVED_EXTENSION_HEADERS: string[] = [
  "X-402-Routing",
  "X-402-Limits",
  "X-402-Acceptable",
  "X-402-Metadata",
  "X-402-Security"
];

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
  return (APPROVED_EXTENSION_HEADERS as string[]).some(
    (ah) => ah.toLowerCase() === h.toLowerCase()
  );
};

// Test-only helper to register additional approved headers at runtime
export function registerApprovedExtensionHeader(header: string): void {
  const exists = APPROVED_EXTENSION_HEADERS.some(
    (h) => h.toLowerCase() === String(header).toLowerCase()
  );
  if (!exists) {
    APPROVED_EXTENSION_HEADERS.push(header);
  }
}

export type X402SecurityPayload = {
  jwksUrl?: string;        // JWKS endpoint URL
  jwks?: any;              // Inline JWKS
  // Minimal security requirements
  minKeyStrength?: number; // Minimum key size
  allowedSuites?: string[]; // Allowed cipher suites
};

