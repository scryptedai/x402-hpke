import sodium from "libsodium-wrappers";
import { buildCanonicalAad, X402Fields } from "./aad.js";
import { jwkToPublicKeyBytes, jwkToPrivateKeyBytes, OkpJwk } from "./keys.js";
import { buildX402Headers } from "./headers.js";
import { createHmac } from "node:crypto";

function b64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function b64uToBytes(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64"));
}

function hkdfSha256(ikm: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const salt = new Uint8Array(32); // zeros
  const prk = createHmac("sha256", Buffer.from(salt)).update(Buffer.from(ikm)).digest();
  const n = Math.ceil(length / 32);
  let t = Buffer.alloc(0);
  let okm = Buffer.alloc(0);
  for (let i = 1; i <= n; i++) {
    const h = createHmac("sha256", prk).update(Buffer.concat([t, Buffer.from(info), Buffer.from([i])])).digest();
    t = h;
    okm = Buffer.concat([okm, h]);
  }
  return new Uint8Array(okm.slice(0, length));
}

export type Envelope = {
  typ: "hpke-envelope";
  ver: "1";
  ns: string;
  kid: string;
  kem: "X25519";
  kdf: "HKDF-SHA256";
  aead: "CHACHA20-POLY1305" | "AES-256-GCM";
  enc: string; // b64url eph public key
  aad: string; // b64url canonical AAD bytes
  ct: string; // b64url ciphertext with tag
};

export async function seal(args: {
  namespace: string;
  kem: "X25519";
  kdf: "HKDF-SHA256";
  aead: "CHACHA20-POLY1305" | "AES-256-GCM";
  kid: string;
  recipientPublicJwk: OkpJwk;
  plaintext: Uint8Array;
  x402: X402Fields;
  app?: Record<string, any>;
  public?: {
    x402Headers?: boolean;
    appHeaderAllowlist?: string[];
    as?: "headers" | "json";
  };
}): Promise<{ envelope: Envelope; publicHeaders?: Record<string, string>; publicJson?: Record<string, string> }> {
  await sodium.ready;
  const { namespace, kem, kdf, aead, kid, recipientPublicJwk, plaintext, x402, app, render } = args;
  if ((plaintext as any) && typeof plaintext === 'object') {
    // guardrail: if caller mistakenly includes x402/app keys in plaintext object, reject in v1 (payload must be opaque bytes)
  }
  const { aadBytes, x402Normalized } = buildCanonicalAad(namespace, x402, app);

  const eph = sodium.crypto_kx_keypair();
  const recipientPub = jwkToPublicKeyBytes(recipientPublicJwk);
  const shared = sodium.crypto_scalarmult(eph.privateKey, recipientPub);

  const info = new TextEncoder().encode(`${namespace}:v1`);
  const okm = hkdfSha256(shared, info, 32 + 24);
  const key = okm.slice(0, 32);
  const nonce = okm.slice(32);

  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aadBytes, null, nonce, key);

  const envelope: Envelope = {
    typ: "hpke-envelope",
    ver: "1",
    ns: namespace,
    kid,
    kem,
    kdf,
    aead,
    enc: b64u(eph.publicKey),
    aad: b64u(aadBytes),
    ct: b64u(ct),
  };

  const as = args.public?.as ?? "headers";
  const wantX402 = !!args.public?.x402Headers;
  const appAllow = args.public?.appHeaderAllowlist ?? [];
  if (!wantX402 && appAllow.length === 0) return { envelope };
  if (as === "headers") {
    const headers: Record<string, string> = {};
    if (wantX402) Object.assign(headers, buildX402Headers(x402Normalized));
    if (appAllow.length > 0 && args.app) {
      for (const k of appAllow) {
        if (!(k in args.app)) throw Object.assign(new Error("PUBLIC_KEY_NOT_IN_AAD"), { code: 400 });
        headers[`X-${args.namespace}-${k.replace(/[^A-Za-z0-9-]/g, "-")}`] = String(args.app[k]);
      }
    }
    return { envelope, publicHeaders: headers };
  } else {
    const json: Record<string, string> = {};
    if (wantX402) Object.assign(json, buildX402Headers(x402Normalized));
    if (appAllow.length > 0 && args.app) {
      for (const k of appAllow) {
        if (!(k in args.app)) throw Object.assign(new Error("PUBLIC_KEY_NOT_IN_AAD"), { code: 400 });
        json[`X-${args.namespace}-${k}`] = String(args.app[k]);
      }
    }
    return { envelope, publicJson: json };
  }
}

export async function open(args: {
  namespace: string;
  kem: "X25519";
  kdf: "HKDF-SHA256";
  aead: "CHACHA20-POLY1305" | "AES-256-GCM";
  expectedKid?: string;
  recipientPrivateJwk: OkpJwk;
  envelope: Envelope;
  publicHeaders?: Record<string, string>;
  publicJson?: Record<string, string>;
}): Promise<{ plaintext: Uint8Array; x402: X402Fields; app?: Record<string, any> }> {
  await sodium.ready;
  const { namespace, expectedKid, recipientPrivateJwk, envelope, headers } = args;
  if (envelope.ver !== "1" || envelope.ns.toLowerCase() === "x402") {
    throw Object.assign(new Error("INVALID_ENVELOPE"), { code: 400 });
  }
  if (expectedKid && envelope.kid !== expectedKid) {
    throw Object.assign(new Error("KID_MISMATCH"), { code: 400 });
  }

  const aadBytes = b64uToBytes(envelope.aad);

  const sidecar = args.publicHeaders ?? args.publicJson;
  if (sidecar) {
    const hx: any = {
      invoiceId: sidecar["X-X402-Invoice-Id"],
      chainId: Number(sidecar["X-X402-Chain-Id"]),
      tokenContract: sidecar["X-X402-Token-Contract"],
      amount: sidecar["X-X402-Amount"],
      recipient: sidecar["X-X402-Recipient"],
      txHash: sidecar["X-X402-Tx-Hash"],
      expiry: Number(sidecar["X-X402-Expiry"]),
      priceHash: sidecar["X-X402-Price-Hash"],
    };
    const rebuilt = buildCanonicalAad(namespace, hx);
    const rebuiltAad = rebuilt.aadBytes;
    if (Buffer.compare(Buffer.from(aadBytes), Buffer.from(rebuiltAad)) !== 0) {
      throw Object.assign(new Error("AAD_MISMATCH"), { code: 400 });
    }
  }

  const sk = jwkToPrivateKeyBytes(recipientPrivateJwk);
  const ephPub = b64uToBytes(envelope.enc);
  const shared = sodium.crypto_scalarmult(sk, ephPub);

  const info = new TextEncoder().encode(`${namespace}:v1`);
  const okm = hkdfSha256(shared, info, 32 + 24);
  const key = okm.slice(0, 32);
  const nonce = okm.slice(32);

  const ct = b64uToBytes(envelope.ct);
  const pt = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, aadBytes, nonce, key);

  const aadStr = Buffer.from(aadBytes).toString("utf8");
  const parts = aadStr.split("|");
  if (parts.length < 4) throw new Error("INVALID_ENVELOPE");
  const xJson = parts[2];
  const appJson = parts[3];
  const x402 = JSON.parse(xJson) as X402Fields;
  const app = appJson ? (JSON.parse(appJson) as Record<string, any>) : undefined;

  return { plaintext: pt, x402, app };
}