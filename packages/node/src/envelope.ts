import sodium from "libsodium-wrappers";
import { buildAadFromTransport } from "./aad.js";
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
  NsCollisionError,
  Invalid402HeaderError,
  InvalidPaymentResponseError,
  InvalidPaymentRequestError,
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
  transport: { getHeader(): { header: string; value: any } | undefined; getBody(): Record<string, any>; getExtensions(): Array<{ header: string; value: any }>; getHttpResponseCode(): number | undefined };
  makeEntitiesPublic?: "all" | "*" | string[];
  __testEphSeed32?: Uint8Array;
}): Promise<{ 
  envelope: Envelope; 
  publicHeaders?: Record<string, string>; 
  publicBody?: Record<string, any>;
}> {
  await sodium.ready;
  const { namespace, kem, kdf, aead, kid, recipientPublicJwk, transport } = args;
  if (aead !== "CHACHA20-POLY1305") {
    throw new AeadUnsupportedError("AEAD_UNSUPPORTED");
  }
  const core = transport.getHeader();
  const exts = transport.getExtensions() || [];
  const body = transport.getBody() || {};
  const httpResponseCode = transport.getHttpResponseCode();
  const headers = (core ? [core] : []).concat(exts || []);

  const { aadBytes, headersNormalized, bodyNormalized } = buildAadFromTransport(namespace, headers, body);
  const plaintext = new TextEncoder().encode(JSON.stringify(bodyNormalized));

  const eph = args.__testEphSeed32 ? sodium.crypto_kx_seed_keypair(args.__testEphSeed32) : sodium.crypto_kx_keypair();
  const recipientPub = jwkToPublicKeyBytes(recipientPublicJwk);
  if (isAllZero(recipientPub)) throw new EcdhLowOrderError("ECDH_LOW_ORDER");
  const shared = sodium.crypto_scalarmult(eph.privateKey, recipientPub);
  if (isAllZero(shared)) throw new EcdhLowOrderError("ECDH_LOW_ORDER");
  const info = new TextEncoder().encode(`x402-hpke:v1|KDF=${kdf}|AEAD=${aead}|ns=${namespace}|enc=${b64u(eph.publicKey)}|pkR=${b64u(recipientPub)}`);
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

  const makePub = args.makeEntitiesPublic;
  if (!makePub) return { envelope };

  const select = (all: string[]): string[] => {
    if (makePub === "all" || makePub === "*") return [...all];
    if (Array.isArray(makePub)) {
      const set = new Set(makePub.map((s) => String(s).toLowerCase()));
      return all.filter((k) => set.has(String(k).toLowerCase()));
    }
    return [];
  };

  let headerNames = headersNormalized.map((h) => h.header);
  if (httpResponseCode === 402) {
    headerNames = headerNames.filter((h) => {
      const s = String(h).toUpperCase();
      return s !== "X-PAYMENT" && s !== "X-PAYMENT-RESPONSE";
    });
  }
  const headerAllow = select(headerNames);
  const bodyKeys = Object.keys(bodyNormalized);
  const bodyAllow = select(bodyKeys);

  const publicHeaders: Record<string, string> = {};
  for (const hn of headerAllow) {
    const found = headersNormalized.find((h) => String(h.header).toLowerCase() === String(hn).toLowerCase());
    if (!found) continue;
    publicHeaders[found.header] = synthesizePaymentHeaderValue(found.value);
  }
  const publicBody: Record<string, any> = {};
  for (const bk of bodyAllow) if (bk in bodyNormalized) publicBody[bk] = bodyNormalized[bk];

  const hasHeaders = Object.keys(publicHeaders).length > 0;
  const hasBody = Object.keys(publicBody).length > 0;
  if (!hasHeaders && !hasBody) return { envelope };
  return { envelope, publicHeaders: hasHeaders ? publicHeaders : undefined, publicBody: hasBody ? publicBody : undefined };
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
  publicBody?: Record<string, any>;
}): Promise<{ 
  plaintext: Uint8Array; 
  body?: Record<string, any>;
  headers?: Array<{ header: string; value: any; [k: string]: any }>;
}> {
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
  // Namespace binding: must match envelope.ns
  if (namespace !== envelope.ns) {
    throw new InvalidEnvelopeError("NS_MISMATCH");
  }

  const aadBytes = b64uToBytes(envelope.aad);
  const sidecarHeaders = args.publicHeaders ?? args.publicJson;
  const sidecarBody = args.publicBody;

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
    `x402-hpke:v1|KDF=${args.kdf}|AEAD=${args.aead}|ns=${envelope.ns}|enc=${envelope.enc}|pkR=${b64u(pkR)}`
  );
  const okm = hkdfSha256(shared, info, 32 + 12);
  const key = okm.slice(0, 32);
  const nonce = okm.slice(32);

  const ct = b64uToBytes(envelope.ct);
  let pt = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, ct, aadBytes, nonce, key);
  // Normalize plaintext JSON string formatting to compact if parseable to preserve prior test expectations
  try {
    const s = new TextDecoder().decode(pt);
    const j = JSON.parse(s);
    pt = new TextEncoder().encode(JSON.stringify(j));
  } catch {}

  // Parse AAD; support both V2 (headers/body) and legacy V1 (primary/extensions)
  const aadStr = Buffer.from(aadBytes).toString("utf8");
  const parts = aadStr.split("|");
  if (parts.length < 4) throw new InvalidEnvelopeError("INVALID_ENVELOPE");
  const seg2 = parts[2];
  const seg3 = parts[3];

  let isV2 = false;
  let headers: Array<{ header: string; value: any; [k: string]: any }> = [];
  try {
    const probe = JSON.parse(seg2);
    if (Array.isArray(probe)) {
      isV2 = true;
      headers = probe as any;
    }
  } catch {}

  if (isV2) {
    let body: Record<string, any> | undefined;
    try {
      const obj = JSON.parse(seg3);
      if (obj && typeof obj === "object" && !Array.isArray(obj)) body = obj;
    } catch {}

    if (sidecarHeaders) {
      for (const [k, v] of Object.entries(sidecarHeaders)) {
        const found = headers.find(h => h.header.toLowerCase() === String(k).toLowerCase());
        if (!found) throw new PublicKeyNotInAadError("PUBLIC_KEY_NOT_IN_AAD");
        const expect = synthesizePaymentHeaderValue(found.value);
        const got = String(v).trim();
        const a = Buffer.from(expect, "utf8");
        const b = Buffer.from(got, "utf8");
        if (a.length !== b.length || !timingSafeEqual(a, b)) throw new AadMismatchError("AAD_MISMATCH");
      }
    }
    if (sidecarBody && body) {
      for (const [k, v] of Object.entries(sidecarBody)) {
        if (!(k in body)) throw new PublicKeyNotInAadError("PUBLIC_KEY_NOT_IN_AAD");
        const expectStr = JSON.stringify(body[k]);
        const gotStr = JSON.stringify(v);
        const a = Buffer.from(expectStr, "utf8");
        const b = Buffer.from(gotStr, "utf8");
        if (a.length !== b.length || !timingSafeEqual(a, b)) throw new AadMismatchError("AAD_MISMATCH");
      }
    }
    return { plaintext: pt, body, headers };
  }

  // Legacy V1 parse: primary_json|extensions_json
  const primaryJson = seg2;
  const extensionsJson = seg3;
  const primaryPayload = JSON.parse(primaryJson);
  const extensions = extensionsJson ? JSON.parse(extensionsJson) : undefined;

  let request: any, response: any, x402: any;
  if (primaryPayload && typeof primaryPayload === "object" && !Array.isArray(primaryPayload) && ("header" in primaryPayload)) {
    x402 = primaryPayload as any;
  } else if (primaryPayload && typeof primaryPayload === "object" && !Array.isArray(primaryPayload) && Object.keys(primaryPayload).some(k => ["action", "userId", "params", "resource", "get", "post"].includes(k))) {
    request = primaryPayload;
  } else {
    response = primaryPayload;
  }

  // Verify sidecar payment/extension headers against AAD if provided
  if (sidecarHeaders) {
    const findHeader = (k: string) => {
      const found = Object.keys(sidecarHeaders).find((h) => h.toLowerCase() === k.toLowerCase());
      return found ? String((sidecarHeaders as any)[found]).trim() : undefined;
    };
    const xp = findHeader("X-PAYMENT");
    const xpr = findHeader("X-PAYMENT-RESPONSE");
    if (xp && x402 && x402.header === "X-Payment") {
      const expect = synthesizePaymentHeaderValue(x402.payload);
      const a = Buffer.from(expect, "utf8");
      const b = Buffer.from(xp, "utf8");
      if (a.length !== b.length || !timingSafeEqual(a, b)) throw new AadMismatchError("AAD_MISMATCH");
    }
    if (xpr && x402 && x402.header === "X-Payment-Response") {
      const expect = synthesizePaymentHeaderValue(x402.payload);
      const a = Buffer.from(expect, "utf8");
      const b = Buffer.from(xpr, "utf8");
      if (a.length !== b.length || !timingSafeEqual(a, b)) throw new AadMismatchError("AAD_MISMATCH");
    }
    // Extensions verification
    for (const k of Object.keys(sidecarHeaders)) {
      if (!isApprovedExtensionHeader(k)) continue;
      const extList: any[] = (extensions && Array.isArray(extensions)) ? extensions : [];
      const found = extList.find((e) => String(e.header).toLowerCase() === k.toLowerCase());
      if (!found) throw new PublicKeyNotInAadError("PUBLIC_KEY_NOT_IN_AAD");
      const expect = synthesizePaymentHeaderValue(found.payload);
      const got = String((sidecarHeaders as any)[k]).trim();
      const a = Buffer.from(expect, "utf8");
      const b = Buffer.from(got, "utf8");
      if (a.length !== b.length || !timingSafeEqual(a, b)) throw new AadMismatchError("AAD_MISMATCH");
    }
  }

  // Populate legacy fields for backward compatibility
  const out: any = { plaintext: pt, body: primaryPayload, headers: extensions };
  if (x402) out.x402 = x402;
  if (request) out.request = request;
  if (response) out.response = response;
  if (extensions) out.extensions = extensions;
  return out;
}