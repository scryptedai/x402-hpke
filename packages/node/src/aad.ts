import { TextEncoder } from "node:util";
import { 
  NsForbiddenError, 
  NsCollisionError,
  X402HeaderError,
  X402PayloadError,
  X402ExtensionUnapprovedError,
  X402ExtensionDuplicateError,
  X402ExtensionPayloadError
} from "./errors.js";
import { X402Extension, isApprovedExtensionHeader, canonicalizeExtensionHeader } from "./extensions.js";

export type X402Core = {
  header: string; // "X-Payment" | "X-Payment-Response" (case-insensitive input)
  payload: Record<string, any>;
  // Additional KV allowed and included in canonicalization
  [k: string]: any;
};

const enc = new TextEncoder();

function deepCanonicalize(value: any): any {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(deepCanonicalize);
  const keys = Object.keys(value).sort();
  const out: any = {};
  for (const k of keys) out[k] = deepCanonicalize(value[k]);
  return out;
}

function canonicalizeHeaderCase(h: string): "X-Payment" | "X-Payment-Response" | "" {
  const s = String(h).toLowerCase();
  if (s === "x-payment") return "X-Payment";
  if (s === "x-payment-response") return "X-Payment-Response";
  if (s === "") return "";
  throw new X402HeaderError("X402_HEADER");
}

export function validateX402Core(x: any): X402Core {
  const header = canonicalizeHeaderCase(x?.header);
  const payload = x?.payload;
  if (header !== "" && (!payload || typeof payload !== "object" || Array.isArray(payload) || Object.keys(payload).length === 0)) {
    throw new X402PayloadError("X402_PAYLOAD");
  }
  const extra: any = {};
  for (const k of Object.keys(x || {})) {
    if (k === "header" || k === "payload") continue;
    extra[k] = x[k];
  }
  return { header, payload, ...extra };
}

function canonicalJson(obj: Record<string, any>): string {
  return JSON.stringify(deepCanonicalize(obj));
}

export function buildCanonicalAad(
  namespace: string,
  payload: {
    request?: Record<string, any>;
    response?: Record<string, any>;
    x402?: X402Core;
  },
  extensions?: X402Extension[]
): {
  aadBytes: Uint8Array;
  x402Normalized?: X402Core;
  requestNormalized?: Record<string, any>;
  responseNormalized?: Record<string, any>;
  extensionsNormalized?: X402Extension[];
} {
  if (!namespace || namespace.toLowerCase() === "x402") throw new NsForbiddenError("NS_FORBIDDEN");
  
  const { request, response, x402 } = payload;
  let primaryJson = "";
  let x402Normalized, requestNormalized, responseNormalized;

  if (x402) {
    const x = validateX402Core(x402);
    primaryJson = canonicalJson(x);
    x402Normalized = JSON.parse(primaryJson);
  } else if (request) {
    primaryJson = canonicalJson(request);
    requestNormalized = JSON.parse(primaryJson);
  } else if (response) {
    primaryJson = canonicalJson(response);
    responseNormalized = JSON.parse(primaryJson);
  }

  let extensionsNormalized;
  let extensionsJson = "";
  if (Array.isArray(extensions) && extensions.length > 0) {
    const seen = new Set<string>();
    const exts: X402Extension[] = [];
    for (const e of extensions as any[]) {
      const hdr = String(e?.header || "");
      if (!isApprovedExtensionHeader(hdr)) throw new X402ExtensionUnapprovedError("X402_EXTENSION_UNAPPROVED");
      const canonHdr = canonicalizeExtensionHeader(hdr);
      if (seen.has(canonHdr.toLowerCase())) throw new X402ExtensionDuplicateError("X402_EXTENSION_DUPLICATE");
      const extPayload = e?.payload;
      if (!extPayload || typeof extPayload !== "object" || Array.isArray(extPayload) || Object.keys(extPayload).length === 0) {
        throw new X402ExtensionPayloadError("X402_EXTENSION_PAYLOAD");
      }
      const extExtra: any = {};
      for (const k2 of Object.keys(e)) if (k2 !== "header" && k2 !== "payload") extExtra[k2] = e[k2];
      exts.push({ header: canonHdr, payload: extPayload, ...extExtra });
      seen.add(canonHdr.toLowerCase());
    }
    // Sort extensions by header (case-insensitive)
    exts.sort((a, b) => a.header.toLowerCase().localeCompare(b.header.toLowerCase()));
    extensionsNormalized = exts.map((e) => deepCanonicalize(e));
    extensionsJson = canonicalJson(extensionsNormalized);
  }
  const prefix = `${namespace}|v1|`;
  const suffix = extensionsJson ? `|${extensionsJson}` : "|";
  const full = prefix + primaryJson + suffix;
  return { 
    aadBytes: enc.encode(full), 
    x402Normalized, 
    requestNormalized, 
    responseNormalized, 
    extensionsNormalized 
  };
}

export function canonicalAad(
  namespace: string, 
  payload: {
    request?: Record<string, any>;
    response?: Record<string, any>;
    x402?: X402Core;
  },
  extensions?: X402Extension[]
): Uint8Array {
  return buildCanonicalAad(namespace, payload, extensions).aadBytes;
}

// V2 refactor types
export type PrivateHeaderEntry = {
  header: string;
  value: any;
  [k: string]: any;
};

export function canonicalizeCoreHeaderName(h: string): "X-Payment" | "X-Payment-Response" | "" | string {
  const s = String(h || "");
  if (s === "") return "";
  const sl = s.toLowerCase();
  if (sl === "x-payment") return "X-Payment";
  if (sl === "x-payment-response") return "X-Payment-Response";
  return s;
}

function canonicalJsonCompact(obj: any): string {
  return JSON.stringify(deepCanonicalize(obj));
}

export function buildCanonicalAadHeadersBody(
  namespace: string,
  privateHeaders?: PrivateHeaderEntry[] | undefined,
  privateBody?: Record<string, any> | undefined
): {
  aadBytes: Uint8Array;
  headersNormalized: Array<{ header: string; value: any; [k: string]: any }>;
  bodyNormalized: Record<string, any>;
} {
  if (!namespace || namespace.toLowerCase() === "x402") throw new NsForbiddenError("NS_FORBIDDEN");

  // Normalize headers
  const headersIn = Array.isArray(privateHeaders) ? privateHeaders : [];
  const seen = new Set<string>();
  const headersNormalized = headersIn.map((e) => {
    const rawHdr = String(e?.header ?? "");
    let hdr = canonicalizeCoreHeaderName(rawHdr);
    if (hdr !== "X-Payment" && hdr !== "X-Payment-Response" && hdr !== "") {
      // extension header path
      if (!isApprovedExtensionHeader(hdr)) {
        throw new X402ExtensionUnapprovedError("X402_EXTENSION_UNAPPROVED");
      }
      hdr = canonicalizeExtensionHeader(hdr);
    }
    const key = hdr.toLowerCase();
    if (seen.has(key)) throw new X402ExtensionDuplicateError("X402_EXTENSION_DUPLICATE");
    seen.add(key);
    const out: any = { ...e };
    out.header = hdr;
    // Canonicalize value structure for AAD stability
    out.value = deepCanonicalize(e?.value);
    return out;
  });
  headersNormalized.sort((a, b) => a.header.toLowerCase().localeCompare(b.header.toLowerCase()));

  // Normalize body
  const bodyNormalized = privateBody ? (deepCanonicalize(privateBody) as Record<string, any>) : {};

  const prefix = `${namespace}|v1|`;
  const headersJson = canonicalJsonCompact(headersNormalized);
  const bodyJson = canonicalJsonCompact(bodyNormalized);
  const full = prefix + headersJson + "|" + bodyJson;
  return { aadBytes: enc.encode(full), headersNormalized, bodyNormalized };
}

// Unified transport AAD builder: uses header names verbatim (no canonicalization),
// deep-canonicalizes values and body, and sorts headers by case-insensitive name for stability
export function buildAadFromTransport(
  namespace: string,
  headers: Array<{ header: string; value: any }>,
  body: Record<string, any>
): {
  aadBytes: Uint8Array;
  headersNormalized: Array<{ header: string; value: any }>;
  bodyNormalized: Record<string, any>;
} {
  if (!namespace || namespace.toLowerCase() === "x402") throw new NsForbiddenError("NS_FORBIDDEN");
  const headersNormalized = (headers || []).map((h) => ({
    header: String(h?.header ?? ""),
    value: deepCanonicalize(h?.value),
  }));
  headersNormalized.sort((a, b) => a.header.toLowerCase().localeCompare(b.header.toLowerCase()));
  const bodyNormalized = deepCanonicalize(body || {}) as Record<string, any>;
  const prefix = `${namespace}|v1|`;
  const headersJson = JSON.stringify(headersNormalized);
  const bodyJson = JSON.stringify(bodyNormalized);
  const full = prefix + headersJson + "|" + bodyJson;
  return { aadBytes: enc.encode(full), headersNormalized, bodyNormalized };
}