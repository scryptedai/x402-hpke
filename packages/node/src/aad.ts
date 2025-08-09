import { TextEncoder } from "node:util";

export type X402Fields = {
  invoiceId: string;
  chainId: number;
  tokenContract: string;
  amount: string;
  recipient: string;
  txHash: string;
  expiry: number;
  priceHash: string;
};

const enc = new TextEncoder();

function isHexPrefixedLower(s: string, len?: number) {
  return /^0x[0-9a-f]+$/.test(s) && (len ? s.length === 2 + len : true);
}

function normalizeHex(input: string, expectedLen?: number): string {
  if (typeof input !== "string") throw new Error("X402_SCHEMA");
  const s = input.toLowerCase();
  if (!s.startsWith("0x")) throw new Error("X402_SCHEMA");
  if (!/^[0-9a-fx]+$/.test(s)) throw new Error("X402_SCHEMA");
  if (expectedLen && s.length !== 2 + expectedLen) throw new Error("X402_SCHEMA");
  return s;
}

function validateAmount(amount: string): string {
  if (typeof amount !== "string") throw new Error("X402_SCHEMA");
  if (!/^(0|[1-9][0-9]*)$/.test(amount)) throw new Error("X402_SCHEMA");
  return amount;
}

export function validateX402(x: any): X402Fields {
  const v: X402Fields = {
    invoiceId: String(x.invoiceId || ""),
    chainId: Number(x.chainId),
    tokenContract: normalizeHex(String(x.tokenContract || ""), 40),
    amount: validateAmount(String(x.amount || "")),
    recipient: normalizeHex(String(x.recipient || ""), 40),
    txHash: normalizeHex(String(x.txHash || ""), 64),
    expiry: Number(x.expiry),
    priceHash: normalizeHex(String(x.priceHash || ""), 64),
  };
  if (!v.invoiceId || !Number.isInteger(v.chainId) || !Number.isInteger(v.expiry)) {
    throw new Error("X402_SCHEMA");
  }
  return v;
}

function canonicalJson(obj: Record<string, any>): string {
  const keys = Object.keys(obj).sort();
  const out: any = {};
  for (const k of keys) out[k] = obj[k];
  return JSON.stringify(out);
}

export function buildCanonicalAad(namespace: string, x402: X402Fields, app?: Record<string, any>): {
  aadBytes: Uint8Array;
  x402Normalized: X402Fields;
  appNormalized?: Record<string, any>;
} {
  if (!namespace || namespace.toLowerCase() === "x402") throw new Error("NS_FORBIDDEN");
  const x = validateX402(x402);
  if (app) {
    for (const k of Object.keys(app)) {
      if (k === "x402" || k.startsWith("x402") || k in x) throw new Error("NS_COLLISION");
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