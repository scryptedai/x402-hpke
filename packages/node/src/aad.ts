import { TextEncoder } from "node:util";
import { NsForbiddenError, NsCollisionError, ReplyToMissingError, ReplyToFormatError } from "./errors.js";

export type X402Fields = {
  invoiceId: string;
  chainId: number;
  tokenContract: string;
  amount: string;
  recipient: string;
  txHash: string;
  expiry: number;
  priceHash: string;
  // optional reply-to hints for responses (one of the two must be present)
  replyToJwks?: string; // https URL to client JWKS
  replyToKid?: string;  // client's key id
  replyToJwk?: { kty: "OKP"; crv: "X25519"; x: string }; // raw client public JWK (fallback)
  replyPublicOk?: boolean; // optional opt-in for plaintext replies
};

const enc = new TextEncoder();

function normalizeHex(input: string, expectedLen?: number): string {
  if (typeof input !== "string") throw new Error("X402_SCHEMA");
  const s = input.toLowerCase();
  if (!s.startsWith("0x")) throw new Error("X402_SCHEMA");
  if (!/^0x[0-9a-f]+$/.test(s)) throw new Error("X402_SCHEMA");
  if (expectedLen && s.length !== 2 + expectedLen) throw new Error("X402_SCHEMA");
  return s;
}

function validateAmount(amount: string): string {
  if (typeof amount !== "string") throw new Error("X402_SCHEMA");
  if (!/^(0|[1-9][0-9]*)$/.test(amount)) throw new Error("X402_SCHEMA");
  return amount;
}

export function validateX402(x: any, opts?: { skipReplyToCheck?: boolean }): X402Fields {
  const v: X402Fields = {
    invoiceId: String(x.invoiceId || ""),
    chainId: Number(x.chainId),
    tokenContract: normalizeHex(String(x.tokenContract || ""), 40),
    amount: validateAmount(String(x.amount || "")),
    recipient: normalizeHex(String(x.recipient || ""), 40),
    txHash: normalizeHex(String(x.txHash || ""), 64),
    expiry: Number(x.expiry),
    priceHash: normalizeHex(String(x.priceHash || ""), 64),
    replyToJwks: x.replyToJwks ? String(x.replyToJwks) : undefined,
    replyToKid: x.replyToKid ? String(x.replyToKid) : undefined,
    replyToJwk: x.replyToJwk,
    replyPublicOk: typeof x.replyPublicOk === "boolean" ? x.replyPublicOk : undefined,
  };
  if (!v.invoiceId || !Number.isInteger(v.chainId) || !Number.isInteger(v.expiry)) {
    throw new Error("X402_SCHEMA");
  }
  if (!opts?.skipReplyToCheck) {
    // Enforce that we have sufficient reply-to info: either (replyToJwks + replyToKid) or (replyToJwk)
    const hasJwks = !!v.replyToJwks && !!v.replyToKid;
    const hasJwk = !!v.replyToJwk && v.replyToJwk.kty === "OKP" && v.replyToJwk.crv === "X25519" && typeof v.replyToJwk.x === "string";
    if (!hasJwks && !hasJwk) {
      throw new ReplyToMissingError("REPLY_TO_REQUIRED");
    }
    if (v.replyToJwks && !/^https:\/\//.test(v.replyToJwks)) {
      throw new ReplyToFormatError("REPLY_TO_JWKS_HTTPS_REQUIRED");
    }
  }
  return v;
}

function canonicalJson(obj: Record<string, any>): string {
  const keys = Object.keys(obj).sort();
  const out: any = {};
  for (const k of keys) out[k] = obj[k];
  return JSON.stringify(out);
}

export function buildCanonicalAad(namespace: string, x402: X402Fields, app?: Record<string, any>, opts?: { skipReplyToCheck?: boolean }): {
  aadBytes: Uint8Array;
  x402Normalized: X402Fields;
  appNormalized?: Record<string, any>;
} {
  if (!namespace || namespace.toLowerCase() === "x402") throw new NsForbiddenError("NS_FORBIDDEN");
  const x = validateX402(x402, opts);
  if (app) {
    for (const k of Object.keys(app)) {
      if (k === "x402" || k.startsWith("x402") || k in x) throw new NsCollisionError("NS_COLLISION");
    }
  }
  const xJson = canonicalJson(x);
  const appJson = app ? canonicalJson(app) : "";
  const prefix = `${namespace}|v1|`;
  const suffix = app ? `|${appJson}` : "|";
  const full = prefix + xJson + suffix;
  return { aadBytes: enc.encode(full), x402Normalized: x, appNormalized: app ? JSON.parse(appJson) : undefined };
}

export function canonicalAad(namespace: string, x402: X402Fields, app?: Record<string, any>): Uint8Array {
  return buildCanonicalAad(namespace, x402, app).aadBytes;
}