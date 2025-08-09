import { TextEncoder } from "node:util";
import { NsForbiddenError, NsCollisionError } from "./errors.js";
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

function canonicalizeHeaderCase(h: string): "X-Payment" | "X-Payment-Response" {
  const s = String(h).toLowerCase();
  if (s === "x-payment") return "X-Payment";
  if (s === "x-payment-response") return "X-Payment-Response";
  throw new Error("X402_HEADER");
}

export function validateX402Core(x: any): X402Core {
  const header = canonicalizeHeaderCase(x?.header);
  const payload = x?.payload;
  if (!payload || typeof payload !== "object" || Array.isArray(payload) || Object.keys(payload).length === 0) {
    throw new Error("X402_PAYLOAD");
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
  x402: X402Core,
  app?: Record<string, any>
): {
  aadBytes: Uint8Array;
  x402Normalized: X402Core;
  appNormalized?: Record<string, any>;
} {
  if (!namespace || namespace.toLowerCase() === "x402") throw new NsForbiddenError("NS_FORBIDDEN");
  const x = validateX402Core(x402);
  // Prepare app normalization with special handling for extensions array
  let normalizedApp: Record<string, any> | undefined;
  if (app) {
    if ("x402" in app || Object.keys(app).some((k) => k.toLowerCase().startsWith("x402"))) {
      throw new NsCollisionError("NS_COLLISION");
    }
    const copy: any = {};
    for (const k of Object.keys(app)) copy[k] = app[k];
    if (Array.isArray(copy.extensions)) {
      const seen = new Set<string>();
      const exts: X402Extension[] = [];
      for (const e of copy.extensions as any[]) {
        const hdr = String(e?.header || "");
        if (!isApprovedExtensionHeader(hdr)) throw new Error("X402_EXTENSION_UNAPPROVED");
        const canonHdr = canonicalizeExtensionHeader(hdr);
        if (seen.has(canonHdr.toLowerCase())) throw new Error("X402_EXTENSION_DUPLICATE");
        const payload = e?.payload;
        if (!payload || typeof payload !== "object" || Array.isArray(payload) || Object.keys(payload).length === 0) {
          throw new Error("X402_EXTENSION_PAYLOAD");
        }
        const extExtra: any = {};
        for (const k2 of Object.keys(e)) if (k2 !== "header" && k2 !== "payload") extExtra[k2] = e[k2];
        exts.push({ header: canonHdr, payload, ...extExtra });
        seen.add(canonHdr.toLowerCase());
      }
      // Sort extensions by header (case-insensitive)
      exts.sort((a, b) => a.header.toLowerCase().localeCompare(b.header.toLowerCase()));
      copy.extensions = exts.map((e) => deepCanonicalize(e));
    }
    normalizedApp = JSON.parse(canonicalJson(copy));
  }
  const xJson = canonicalJson(x);
  const appJson = normalizedApp ? canonicalJson(normalizedApp) : "";
  const prefix = `${namespace}|v1|`;
  const suffix = normalizedApp ? `|${appJson}` : "|";
  const full = prefix + xJson + suffix;
  return { aadBytes: enc.encode(full), x402Normalized: JSON.parse(xJson), appNormalized: normalizedApp };
}

export function canonicalAad(namespace: string, x402: X402Core, app?: Record<string, any>): Uint8Array {
  return buildCanonicalAad(namespace, x402, app).aadBytes;
}