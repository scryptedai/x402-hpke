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