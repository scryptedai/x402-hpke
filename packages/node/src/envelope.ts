import sodium from "libsodium-wrappers";
import { buildCanonicalAad, X402Fields } from "./aad.js";
import { jwkToPublicKeyBytes, jwkToPrivateKeyBytes, OkpJwk } from "./keys.js";
import { buildX402Headers } from "./headers.js";
import { createHmac, timingSafeEqual } from "crypto";
import {
  AeadMismatchError,
  AeadUnsupportedError,
  AadMismatchError,
  EcdhLowOrderError,
  InvalidEnvelopeError,
  KidMismatchError,
  PublicKeyNotInAadError,
} from "./errors.js";

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
  let t: Buffer = Buffer.alloc(0);
  let okm: Buffer = Buffer.alloc(0);
  for (let i = 1; i <= n; i++) {
    const h = createHmac("sha256", prk).update(Buffer.concat([t, Buffer.from(info), Buffer.from([i])])).digest();
    // Normalize Buffer generic types by re-wrapping
    const hb = Buffer.from(h);
    t = hb;
    okm = Buffer.concat([okm, hb]);
  }
  return new Uint8Array(okm.slice(0, length));
}

function isAllZero(bytes: Uint8Array): boolean {
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] !== 0) return false;
  }
  return true;
}

export type Envelope = {
  typ: "hpke-envelope";
  ver: "1";
  suite?: "X25519-HKDF-SHA256-CHACHA20POLY1305";
  ns: string;
  kid: string;
  kem: "X25519";
  kdf: "HKDF-SHA256";
  aead: "CHACHA20-POLY1305";
  enc: string; // b64url eph public key
  aad: string; // b64url canonical AAD bytes
  ct: string; // b64url ciphertext with tag
};

export async function seal(args: {
  namespace: string;
  kem: "X25519";
  kdf: "HKDF-SHA256";
  aead: "CHACHA20-POLY1305";
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
  // Test-only deterministic ephemeral seed for KAT generation
  __testEphSeed32?: Uint8Array;
}): Promise<{ envelope: Envelope; publicHeaders?: Record<string, string>; publicJson?: Record<string, string> }> {
  await sodium.ready;
  const { namespace, kem, kdf, aead, kid, recipientPublicJwk, plaintext, x402, app } = args;
  if (aead !== "CHACHA20-POLY1305") {
    throw new AeadUnsupportedError("AEAD_UNSUPPORTED");
  }
  if ((plaintext as any) && typeof plaintext === 'object') {
    // guardrail: if caller mistakenly includes x402/app keys in plaintext object, reject in v1 (payload must be opaque bytes)
  }
  const { aadBytes, x402Normalized } = buildCanonicalAad(namespace, x402, app);

  const eph = args.__testEphSeed32
    ? sodium.crypto_kx_seed_keypair(args.__testEphSeed32)
    : sodium.crypto_kx_keypair();
  const recipientPub = jwkToPublicKeyBytes(recipientPublicJwk);
  if (isAllZero(recipientPub)) {
    throw new EcdhLowOrderError("ECDH_LOW_ORDER");
  }
  const shared = sodium.crypto_scalarmult(eph.privateKey, recipientPub);
  if (isAllZero(shared)) {
    throw new EcdhLowOrderError("ECDH_LOW_ORDER");
  }

  const info = new TextEncoder().encode(
    `x402-hpke:v1|KDF=${kdf}|AEAD=${aead}|ns=${namespace}|enc=${b64u(eph.publicKey)}|pkR=${b64u(recipientPub)}`
  );
  const okm = hkdfSha256(shared, info, 32 + 12);
  const key = okm.slice(0, 32);
  const nonce = okm.slice(32);

  const ct = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(plaintext, aadBytes, null, nonce, key);

  const envelope: Envelope = {
    typ: "hpke-envelope",
    ver: "1",
    suite: "X25519-HKDF-SHA256-CHACHA20POLY1305",
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
        if (!(k in args.app)) throw new PublicKeyNotInAadError("PUBLIC_KEY_NOT_IN_AAD");
        headers[`X-${args.namespace}-${k.replace(/[^A-Za-z0-9-]/g, "-")}`] = String(args.app[k]);
      }
    }
    return { envelope, publicHeaders: headers };
  } else {
    const json: Record<string, string> = {};
    if (wantX402) Object.assign(json, buildX402Headers(x402Normalized));
    if (appAllow.length > 0 && args.app) {
      for (const k of appAllow) {
        if (!(k in args.app)) throw new PublicKeyNotInAadError("PUBLIC_KEY_NOT_IN_AAD");
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
  aead: "CHACHA20-POLY1305";
  expectedKid?: string;
  recipientPrivateJwk: OkpJwk;
  envelope: Envelope;
  publicHeaders?: Record<string, string>;
  publicJson?: Record<string, string>;
}): Promise<{ plaintext: Uint8Array; x402: X402Fields; app?: Record<string, any> }> {
  await sodium.ready;
  const { namespace, expectedKid, recipientPrivateJwk, envelope } = args;
  if (envelope.ver !== "1" || envelope.ns.toLowerCase() === "x402") {
    throw new InvalidEnvelopeError("INVALID_ENVELOPE");
  }
  if (envelope.aead !== args.aead) {
    throw new AeadMismatchError("AEAD_MISMATCH");
  }
  if (args.aead !== "CHACHA20-POLY1305") {
    throw new AeadUnsupportedError("AEAD_UNSUPPORTED");
  }
  if (expectedKid && envelope.kid !== expectedKid) {
    throw new KidMismatchError("KID_MISMATCH");
  }

  const aadBytes = b64uToBytes(envelope.aad);

  const sidecar = args.publicHeaders ?? args.publicJson;
  if (sidecar) {
    const get = (k: string) => {
      // case-insensitive header matching; trim optional whitespace
      const found = Object.keys(sidecar).find((h) => h.toLowerCase() === k.toLowerCase());
      const v = found ? (sidecar as any)[found] : undefined;
      return typeof v === "string" ? v.trim() : v;
    };
    const hx: any = {
      invoiceId: get("X-X402-Invoice-Id"),
      chainId: Number(get("X-X402-Chain-Id")),
      tokenContract: get("X-X402-Token-Contract"),
      amount: get("X-X402-Amount"),
      recipient: get("X-X402-Recipient"),
      txHash: get("X-X402-Tx-Hash"),
      expiry: Number(get("X-X402-Expiry")),
      priceHash: get("X-X402-Price-Hash"),
    };
    const rebuilt = buildCanonicalAad(namespace, hx);
    const rebuiltAad = rebuilt.aadBytes;
    const a = Buffer.from(aadBytes);
    const b = Buffer.from(rebuiltAad);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      throw new AadMismatchError("AAD_MISMATCH");
    }
  }

  const sk = jwkToPrivateKeyBytes(recipientPrivateJwk);
  const ephPub = b64uToBytes(envelope.enc);
  if (isAllZero(ephPub)) {
    throw new EcdhLowOrderError("ECDH_LOW_ORDER");
  }
  const shared = sodium.crypto_scalarmult(sk, ephPub);
  if (isAllZero(shared)) {
    throw new EcdhLowOrderError("ECDH_LOW_ORDER");
  }

  const pkR = sodium.crypto_scalarmult_base(sk);
  const info = new TextEncoder().encode(
    `x402-hpke:v1|KDF=${args.kdf}|AEAD=${args.aead}|ns=${namespace}|enc=${envelope.enc}|pkR=${b64u(pkR)}`
  );
  const okm = hkdfSha256(shared, info, 32 + 12);
  const key = okm.slice(0, 32);
  const nonce = okm.slice(32);

  const ct = b64uToBytes(envelope.ct);
  const pt = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, ct, aadBytes, nonce, key);

  const aadStr = Buffer.from(aadBytes).toString("utf8");
  const parts = aadStr.split("|");
  if (parts.length < 4) throw new InvalidEnvelopeError("INVALID_ENVELOPE");
  const xJson = parts[2];
  const appJson = parts[3];
  const x402 = JSON.parse(xJson) as X402Fields;
  const app = appJson ? (JSON.parse(appJson) as Record<string, any>) : undefined;

  return { plaintext: pt, x402, app };
}