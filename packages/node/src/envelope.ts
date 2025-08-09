import sodium from "libsodium-wrappers";
import { buildCanonicalAad, X402Core } from "./aad.js";
import { jwkToPublicKeyBytes, jwkToPrivateKeyBytes, OkpJwk } from "./keys.js";
import { synthesizePaymentHeaderValue } from "./payment.js";
import { isApprovedExtensionHeader } from "./extensions.js";
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
  x402: X402Core;
  app?: Record<string, any>;
  // Optional HTTP response code to determine sidecar behavior
  httpResponseCode?: number;
  public?: {
    as?: "headers" | "json";
    // makeEntitiesPublic determines which entities (core payment and/or approved extensions) are emitted
    makeEntitiesPublic?: "all" | "*" | string[];
    // makeEntitiesPrivate subtracts matches from the public set (post-processing)
    makeEntitiesPrivate?: string[];
  };
  // Test-only deterministic ephemeral seed for KAT generation
  __testEphSeed32?: Uint8Array;
}): Promise<{ envelope: Envelope; publicHeaders?: Record<string, string>; publicJson?: Record<string, string> }> {
  await sodium.ready;
  const { namespace, kem, kdf, aead, kid, recipientPublicJwk, plaintext, x402, app } = args;
  // No legacy sidecar preflight; only extensions allowlist handled below
  if (aead !== "CHACHA20-POLY1305") {
    throw new AeadUnsupportedError("AEAD_UNSUPPORTED");
  }
  if ((plaintext as any) && typeof plaintext === 'object') {
    // guardrail: if caller mistakenly includes x402/app keys in plaintext object, reject in v1 (payload must be opaque bytes)
  }
  const { aadBytes, x402Normalized, appNormalized } = buildCanonicalAad(namespace, x402, app);

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
  const httpResponseCode = args.httpResponseCode;
  
  // Three use cases for sidecar generation:
  // 1. Client request (no httpResponseCode): Can include X-PAYMENT in sidecar
  // 2. 402 response: No X-402 headers sent (but body is encrypted)
  // 3. Success response (200+): Can include X-PAYMENT-RESPONSE in sidecar
  
  // For 402 responses, never send X-402 headers in sidecar
  if (httpResponseCode === 402) {
    // Only emit approved extensions if explicitly requested
    let extAllow: string[] = [];
    const makePub = args.public?.makeEntitiesPublic;
    if (makePub === "all" || makePub === "*") {
      if (appNormalized && Array.isArray(appNormalized.extensions)) {
        extAllow = appNormalized.extensions
          .map((e: any) => String(e.header))
          .filter((h: string) => isApprovedExtensionHeader(h));
      }
    } else if (Array.isArray(makePub)) {
      // For 402, only process approved extension headers, ignore core payment headers
      extAllow = makePub
        .filter((h: string) => isApprovedExtensionHeader(h));
    }
    
    // Apply makeEntitiesPrivate filter
    const makePriv = args.public?.makeEntitiesPrivate;
    if (Array.isArray(makePriv)) {
      const privSet = new Set(makePriv.map((s) => String(s).toUpperCase()));
      extAllow = extAllow.filter((h) => !privSet.has(String(h).toUpperCase()));
    }
    
    // 402 responses only emit extensions, never core payment headers
    if (extAllow.length === 0) return { envelope };
    
    if (as === "headers") {
      const headers: Record<string, string> = {};
      if (extAllow.length > 0 && appNormalized && Array.isArray(appNormalized.extensions)) {
        for (const wanted of extAllow) {
          if (!isApprovedExtensionHeader(wanted)) continue;
          const found = appNormalized.extensions.find((e: any) => String(e.header).toLowerCase() === wanted.toLowerCase());
          if (!found) throw new PublicKeyNotInAadError("PUBLIC_KEY_NOT_IN_AAD");
          headers[found.header] = synthesizePaymentHeaderValue(found.payload);
        }
      }
      return { envelope, publicHeaders: headers };
    } else {
      const json: Record<string, string> = {};
      if (extAllow.length > 0 && appNormalized && Array.isArray(appNormalized.extensions)) {
        for (const wanted of extAllow) {
          if (!isApprovedExtensionHeader(wanted)) continue;
          const found = appNormalized.extensions.find((e: any) => String(e.header).toLowerCase() === wanted.toLowerCase());
          if (!found) throw new PublicKeyNotInAadError("PUBLIC_KEY_NOT_IN_AAD");
          json[found.header] = synthesizePaymentHeaderValue(found.payload);
        }
      }
      return { envelope, publicJson: json };
    }
  }
  
  // For non-402 responses (including client requests), handle normal sidecar logic
  // Compute which extensions to emit
  let extAllow: string[] = [];
  const makePub = args.public?.makeEntitiesPublic;
  if (makePub === "all" || makePub === "*") {
    if (appNormalized && Array.isArray(appNormalized.extensions)) {
      extAllow = appNormalized.extensions
        .map((e: any) => String(e.header))
        .filter((h: string) => isApprovedExtensionHeader(h));
    }
  } else if (Array.isArray(makePub)) {
    extAllow = makePub.slice();
  }
  
  // Decide if core payment header should be emitted via makePublic
  let wantPayment = Array.isArray(makePub)
    ? (makePub as string[]).some((h) => ["X-PAYMENT", "X-PAYMENT-RESPONSE"].includes(String(h).toUpperCase()))
    : makePub === "all" || makePub === "*";
    
  // Apply makeEntitiesPrivate subtraction
  const makePriv = args.public?.makeEntitiesPrivate;
  if (Array.isArray(makePriv)) {
    const privSet = new Set(makePriv.map((s) => String(s).toUpperCase()));
    extAllow = extAllow.filter((h) => !privSet.has(String(h).toUpperCase()));
    if (wantPayment) {
      if (privSet.has("X-PAYMENT") && x402Normalized.header === "X-Payment") wantPayment = false;
      if (privSet.has("X-PAYMENT-RESPONSE") && x402Normalized.header === "X-Payment-Response") wantPayment = false;
    }
  }
  
  if (!wantPayment && extAllow.length === 0) return { envelope };
  
  if (as === "headers") {
    const headers: Record<string, string> = {};
    if (wantPayment) {
      const h = x402Normalized.header.toUpperCase() === "X-PAYMENT" ? "X-PAYMENT" : "X-PAYMENT-RESPONSE";
      headers[h] = synthesizePaymentHeaderValue(x402Normalized.payload);
    }
    if (extAllow.length > 0 && appNormalized && Array.isArray(appNormalized.extensions)) {
      for (const wanted of extAllow) {
        if (!isApprovedExtensionHeader(wanted)) continue;
        const found = appNormalized.extensions.find((e: any) => String(e.header).toLowerCase() === wanted.toLowerCase());
        if (!found) throw new PublicKeyNotInAadError("PUBLIC_KEY_NOT_IN_AAD");
        headers[found.header] = synthesizePaymentHeaderValue(found.payload);
      }
    }
    return { envelope, publicHeaders: headers };
  } else {
    const json: Record<string, string> = {};
    if (wantPayment) {
      const h = x402Normalized.header.toUpperCase() === "X-PAYMENT" ? "X-PAYMENT" : "X-PAYMENT-RESPONSE";
      json[h] = synthesizePaymentHeaderValue(x402Normalized.payload);
    }
    if (extAllow.length > 0 && appNormalized && Array.isArray(appNormalized.extensions)) {
      for (const wanted of extAllow) {
        if (!isApprovedExtensionHeader(wanted)) continue;
        const found = appNormalized.extensions.find((e: any) => String(e.header).toLowerCase() === wanted.toLowerCase());
        if (!found) throw new PublicKeyNotInAadError("PUBLIC_KEY_NOT_IN_AAD");
        json[found.header] = synthesizePaymentHeaderValue(found.payload);
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
}): Promise<{ plaintext: Uint8Array; x402: X402Core; app?: Record<string, any> }> {
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
  const x402 = JSON.parse(xJson) as X402Core;
  const app = appJson ? (JSON.parse(appJson) as Record<string, any>) : undefined;

  // Verify sidecar payment/extension headers against AAD if provided
  if (sidecar) {
    const findHeader = (k: string) => {
      const found = Object.keys(sidecar).find((h) => h.toLowerCase() === k.toLowerCase());
      return found ? String((sidecar as any)[found]).trim() : undefined;
    };
    const xp = findHeader("X-PAYMENT");
    const xpr = findHeader("X-PAYMENT-RESPONSE");
    if (xp && x402.header === "X-Payment") {
      const expect = synthesizePaymentHeaderValue(x402.payload);
      if (xp !== expect) throw new AadMismatchError("AAD_MISMATCH");
    }
    if (xpr && x402.header === "X-Payment-Response") {
      const expect = synthesizePaymentHeaderValue(x402.payload);
      if (xpr !== expect) throw new AadMismatchError("AAD_MISMATCH");
    }
    // Extensions verification
    for (const k of Object.keys(sidecar)) {
      if (!isApprovedExtensionHeader(k)) continue;
      const extList: any[] = (app && Array.isArray((app as any).extensions)) ? (app as any).extensions : [];
      const found = extList.find((e) => String(e.header).toLowerCase() === k.toLowerCase());
      if (!found) throw new PublicKeyNotInAadError("PUBLIC_KEY_NOT_IN_AAD");
      const expect = synthesizePaymentHeaderValue(found.payload);
      const got = String((sidecar as any)[k]).trim();
      if (got !== expect) throw new AadMismatchError("AAD_MISMATCH");
    }
  }

  // Legacy payment/app sidecar verification removed; only verify against core and extensions

  return { plaintext: pt, x402, app };
}