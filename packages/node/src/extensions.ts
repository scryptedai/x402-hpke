export const APPROVED_EXTENSION_HEADERS = [
  "X-402-Routing",
  "X-402-Limits",
  "X-402-Acceptable",
  "X-402-Metadata",
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
  if (!found) throw new Error("X402_EXTENSION_UNAPPROVED");
  return found;
}

