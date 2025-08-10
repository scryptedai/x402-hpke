import sodium from "libsodium-wrappers";
import { 
  buildCanonicalAad, 
  X402Core, 
  buildCanonicalAadHeadersBody, 
  type PrivateHeaderEntry, 
  canonicalizeCoreHeaderName, 
  deepCanonicalize,
} from "./aad.js";
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
  // New V2 inputs
  privateHeaders?: PrivateHeaderEntry[];
  privateBody?: Record<string, any>;
  request?: Record<string, any>;
  response?: Record<string, any>;
  x402?: X402Core;
  extensions?: X402Extension[];
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
}): Promise<{ 
  envelope: Envelope; 
  publicHeaders?: Record<string, string>; 
  publicJson?: Record<string, string>;
  publicJsonBody?: Record<string, any>;
  publicBody?: Record<string, any>;
}> {
  await sodium.ready;
  const { namespace, kem, kdf, aead, kid, recipientPublicJwk } = args;
  
  let httpResponseCode = args.httpResponseCode;

  // V2 path when privateHeaders/body present
  const useHeadersBody = Array.isArray(args.privateHeaders) || args.privateBody !== undefined;
  if (useHeadersBody) {
    const hdrs: PrivateHeaderEntry[] = Array.isArray(args.privateHeaders) ? [...args.privateHeaders!] : [];
    let body: Record<string, any> = args.privateBody ? { ...args.privateBody } : {};

    // Validate collisions: body keys cannot equal any header names
    const headerNamesLower = new Set(hdrs.map(h => String(h.header).toLowerCase()));
    for (const k of Object.keys(body)) {
      if (headerNamesLower.has(k.toLowerCase())) {
        throw new InvalidEnvelopeError("BODY_HEADER_NAME_COLLISION");
      }
    }

    // Identify core x402 headers
    const coreHdrs = hdrs
      .map((h, i) => ({ i, name: canonicalizeCoreHeaderName(h.header), entry: h }))
      .filter(x => x.name === "X-Payment" || x.name === "X-Payment-Response" || x.name === "");
    // Ensure uniqueness among core headers
    const coreKinds = new Set(coreHdrs.map(x => x.name));
    if (coreKinds.size > 1) {
      throw new InvalidEnvelopeError("MULTIPLE_CORE_X402_HEADERS");
    }
    if (coreHdrs.length > 1) {
      // same header duplicated
      throw new InvalidEnvelopeError("DUPLICATE_CORE_X402_HEADER");
    }

    if (coreHdrs.length === 1) {
      const core = coreHdrs[0];
      if (core.name === "X-Payment") {
        if (httpResponseCode !== undefined) {
          throw new InvalidPaymentRequestError("X_PAYMENT_STATUS");
        }
        // Require at least payload field
        const val = core.entry?.value;
        if (!val || typeof val !== "object" || Array.isArray(val) || !("payload" in val)) {
          throw new InvalidPaymentRequestError("X_PAYMENT_PAYLOAD");
        }
      } else if (core.name === "X-Payment-Response") {
        if (httpResponseCode === undefined) httpResponseCode = 200;
        if (httpResponseCode !== 200) {
          throw new InvalidPaymentResponseError("X_PAYMENT_RESPONSE_STATUS");
        }
      } else if (core.name === "") {
        // Payment Required: move value into body; ensure 402
        if (httpResponseCode === undefined) httpResponseCode = 402;
        if (httpResponseCode !== 402) {
          throw new Invalid402HeaderError("INVALID_402_HEADER_STATUS");
        }
        const val = core.entry?.value ?? {};
        // Merge if body empty, else prefer existing body keys (no deep merge to avoid ambiguity)
        if (!args.privateBody || Object.keys(body).length === 0) {
          body = (val && typeof val === "object") ? { ...val } : {};
        }
        // Remove the empty header from headers list
        hdrs.splice(core.i, 1);
      }
    }

    // Build canonical AAD v2
    const { aadBytes, headersNormalized, bodyNormalized } = buildCanonicalAadHeadersBody(namespace, hdrs, body);

    // Encrypt plaintext as JSON(body)
    const plaintext = new TextEncoder().encode(JSON.stringify(bodyNormalized));

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
    const makePub = args.public?.makeEntitiesPublic;
    const makePriv = args.public?.makeEntitiesPrivate ?? [];

    const makeSet = (allKeys: string[]): string[] => {
      let s: string[] = [];
      if (makePub === "all" || makePub === "*") s = [...allKeys];
      else if (Array.isArray(makePub)) s = allKeys.filter(k => makePub.map(x => String(x)).some(y => y.toLowerCase() === k.toLowerCase()));
      // subtract priv
      const privSet = new Set(makePriv.map(x => String(x).toLowerCase()));
      s = s.filter(k => !privSet.has(k.toLowerCase()));
      return s;
    };

    // Headers public projection
    const headerNames = headersNormalized.map(h => h.header);
    let headerAllow = makeSet(headerNames);
    if (httpResponseCode === 402) {
      // Remove core headers under 402
      headerAllow = headerAllow.filter(h => {
        const canon = canonicalizeCoreHeaderName(h);
        return !(canon === "X-Payment" || canon === "X-Payment-Response");
      });
    }

    // Body public projection (top-level keys only)
    const bodyKeys = Object.keys(bodyNormalized);
    const bodyAllow = makeSet(bodyKeys);

    if (as === "headers") {
      const headersOut: Record<string, string> = {};
      for (const hn of headerAllow) {
        const found = headersNormalized.find(h => h.header.toLowerCase() === hn.toLowerCase());
        if (!found) continue;
        const canon = canonicalizeCoreHeaderName(found.header);
        const keyName = canon === "X-Payment" ? "X-PAYMENT" : canon === "X-Payment-Response" ? "X-PAYMENT-RESPONSE" : found.header;
        headersOut[keyName] = synthesizePaymentHeaderValue(found.value);
      }
      if (Object.keys(headersOut).length > 0) return { envelope, publicHeaders: headersOut };
      return { envelope };
    } else {
      const publicJson: Record<string, string> = {};
      for (const hn of headerAllow) {
        const found = headersNormalized.find(h => h.header.toLowerCase() === hn.toLowerCase());
        if (!found) continue;
        const canon = canonicalizeCoreHeaderName(found.header);
        const keyName = canon === "X-Payment" ? "X-PAYMENT" : canon === "X-Payment-Response" ? "X-PAYMENT-RESPONSE" : found.header;
        publicJson[keyName] = synthesizePaymentHeaderValue(found.value);
      }
      const publicBody: Record<string, any> = {};
      for (const bk of bodyAllow) {
        if (bk in bodyNormalized) publicBody[bk] = bodyNormalized[bk];
      }
      if (Object.keys(publicJson).length || Object.keys(publicBody).length) return { envelope, publicJson, publicBody };
      return { envelope };
    }
  }

  // Legacy V1 path (request/response/x402 + extensions)
  const { request, response, x402, extensions } = args as any;

  // Rule 1: Mutually Exclusive Payloads
  const payloadCount = [request, response, x402].filter(p => p !== undefined).length;
  if (payloadCount > 1) {
    throw new Error("MUTUALLY_EXCLUSIVE_PAYLOAD: Only one of 'request', 'response', or 'x402' can be provided.");
  }
  if (payloadCount === 0) {
    throw new Error("PAYLOAD_REQUIRED: One of 'request', 'response', or 'x402' must be provided.");
  }

  // Rule 2: The `request` Object
  if (request) {
    if (httpResponseCode !== undefined) {
      throw new Error("INVALID_REQUEST_PARAMS: 'httpResponseCode' is not allowed for 'request' payloads.");
    }
  }

  // Rule 3: The `response` Object
  if (response) {
    if (httpResponseCode === undefined) {
      throw new Error("INVALID_RESPONSE_PARAMS: 'httpResponseCode' is required for 'response' payloads.");
    }
  }

  // Rule 4: The `x402` Object
  if (x402) {
    if (httpResponseCode === 200 && x402.header !== "X-Payment-Response") {
      throw new Error("INVALID_200_X402: For httpResponseCode 200, x402.header must be 'X-Payment-Response'.");
    }
    if (httpResponseCode === 402 && x402.header !== "") {
      throw new Error("INVALID_402_X402: For httpResponseCode 402, x402.header must be an empty string.");
    }
    if (httpResponseCode === undefined) {
      if (x402.header === "X-Payment-Response") {
        httpResponseCode = 200;
      } else if (x402.header === "") {
        httpResponseCode = 402;
      }
    }
  }
  
  // No legacy sidecar preflight; only extensions allowlist handled below
  if (aead !== "CHACHA20-POLY1305") {
    throw new AeadUnsupportedError("AEAD_UNSUPPORTED");
  }

  // Automatically determine what to encrypt based on the payload type
  let plaintext: Uint8Array;
  if (request) {
    plaintext = new TextEncoder().encode(JSON.stringify(request));
  } else if (response) {
    plaintext = new TextEncoder().encode(JSON.stringify(response));
  } else if (x402) {
    // For 402 with empty header, legacy behavior: plaintext is the payload object
    if (httpResponseCode === 402 && x402.header === "") {
      plaintext = new TextEncoder().encode(JSON.stringify(x402.payload ?? {}));
    } else {
      plaintext = new TextEncoder().encode(JSON.stringify(x402));
    }
  } else {
    // This should never happen due to the validation above, but TypeScript needs this
    plaintext = new Uint8Array();
  }

  const { aadBytes, x402Normalized, appNormalized, extensionsNormalized } = buildCanonicalAad(
    namespace, 
    { request, response, x402 },
    extensions
  );

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
  
  // Sidecar Generation
  const makePub = args.public?.makeEntitiesPublic;
  if (makePub) {
    if ((makePub === "all" || makePub === "*" || makePub.includes("request")) && request) {
      return { envelope, publicJsonBody: request };
    }
    if ((makePub === "all" || makePub === "*" || makePub.includes("response")) && response) {
      return { envelope, publicJsonBody: response };
    }
  }

  // Three use cases for sidecar generation:
  // 1. Client request (no httpResponseCode): Can include X-PAYMENT in sidecar
  // 2. 402 response: No X-402 headers sent (but body is encrypted)
  // 3. Success response (200+): Can include X-PAYMENT-RESPONSE in sidecar
  
  // For 402 responses, never send X-402 headers in sidecar
  if (httpResponseCode === 402) {
    // Only emit approved extensions if explicitly requested
    let extAllow: string[] = [];
    const makePub402 = args.public?.makeEntitiesPublic;
    if (makePub402 === "all" || makePub402 === "*") {
      if (extensionsNormalized && Array.isArray(extensionsNormalized)) {
        extAllow = extensionsNormalized
          .map((e: any) => String(e.header))
          .filter((h: string) => isApprovedExtensionHeader(h));
      }
    } else if (Array.isArray(makePub402)) {
      // For 402, only process approved extension headers, ignore core payment headers
      extAllow = makePub402
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
      if (extAllow.length > 0 && extensionsNormalized && Array.isArray(extensionsNormalized)) {
        for (const wanted of extAllow) {
          if (!isApprovedExtensionHeader(wanted)) continue;
          const found = extensionsNormalized.find((e: any) => String(e.header).toLowerCase() === wanted.toLowerCase());
          if (!found) throw new PublicKeyNotInAadError("PUBLIC_KEY_NOT_IN_AAD");
          headers[found.header] = synthesizePaymentHeaderValue(found.payload);
        }
      }
      return { envelope, publicHeaders: headers };
    } else {
      const json: Record<string, string> = {};
      if (extAllow.length > 0 && extensionsNormalized && Array.isArray(extensionsNormalized)) {
        for (const wanted of extAllow) {
          if (!isApprovedExtensionHeader(wanted)) continue;
          const found = extensionsNormalized.find((e: any) => String(e.header).toLowerCase() === wanted.toLowerCase());
          if (!found) throw new PublicKeyNotInAadError("PUBLIC_KEY_NOT_IN_AAD");
          json[found.header] = synthesizePaymentHeaderValue(found.payload);
        }
      }
      return { envelope, publicJson: json };
    }
  }

  // For non-402 responses and client requests, can emit both payment headers and extensions
  if (as === "headers") {
    const headers: Record<string, string> = {};
    
    // Emit x402 headers if requested and available
    if (x402 && args.public?.makeEntitiesPublic) {
      const makePub = args.public.makeEntitiesPublic;
      const wantsAll = makePub === "all" || makePub === "*";
      const wants = Array.isArray(makePub) ? new Set(makePub.map((s) => String(s).toUpperCase())) : new Set<string>();
      if (wantsAll || wants.has("X-PAYMENT") || wants.has("X-PAYMENT-RESPONSE")) {
        if (x402.header === "X-Payment") {
          headers["X-PAYMENT"] = synthesizePaymentHeaderValue(x402.payload);
        } else if (x402.header === "X-Payment-Response") {
          headers["X-PAYMENT-RESPONSE"] = synthesizePaymentHeaderValue(x402.payload);
        }
      }
    }
    
    // Emit extension headers if requested and available
    if (extensionsNormalized && Array.isArray(extensionsNormalized) && args.public?.makeEntitiesPublic) {
      const makePub = args.public.makeEntitiesPublic;
      let extAllow: string[] = [];
      if (makePub === "all" || makePub === "*") {
        extAllow = extensionsNormalized
          .map((e: any) => String(e.header))
          .filter((h: string) => isApprovedExtensionHeader(h));
      } else if (Array.isArray(makePub)) {
        extAllow = makePub
          .filter((h: string) => isApprovedExtensionHeader(h));
      }
      
      // Apply makeEntitiesPrivate filter
      const makePriv = args.public?.makeEntitiesPrivate;
      if (Array.isArray(makePriv)) {
        const privSet = new Set(makePriv.map((s) => String(s).toUpperCase()));
        extAllow = extAllow.filter((h) => !privSet.has(String(h).toUpperCase()));
      }
      
      for (const wanted of extAllow) {
        if (!isApprovedExtensionHeader(wanted)) continue;
        const found = extensionsNormalized.find((e: any) => String(e.header).toLowerCase() === wanted.toLowerCase());
        if (!found) throw new PublicKeyNotInAadError("PUBLIC_KEY_NOT_IN_AAD");
        headers[found.header] = synthesizePaymentHeaderValue(found.payload);
      }
    }
    
    if (Object.keys(headers).length > 0) {
      return { envelope, publicHeaders: headers };
    }
  } else {
    const json: Record<string, string> = {};
    
    // Emit x402 headers if requested and available
    if (x402 && args.public?.makeEntitiesPublic) {
      const makePub = args.public.makeEntitiesPublic;
      const wantsAll = makePub === "all" || makePub === "*";
      const wants = Array.isArray(makePub) ? new Set(makePub.map((s) => String(s).toUpperCase())) : new Set<string>();
      if (wantsAll || wants.has("X-PAYMENT") || wants.has("X-PAYMENT-RESPONSE")) {
        if (x402.header === "X-Payment") {
          json["X-PAYMENT"] = synthesizePaymentHeaderValue(x402.payload);
        } else if (x402.header === "X-Payment-Response") {
          json["X-PAYMENT-RESPONSE"] = synthesizePaymentHeaderValue(x402.payload);
        }
      }
    }
    
    // Emit extension headers if requested and available
    if (extensionsNormalized && Array.isArray(extensionsNormalized) && args.public?.makeEntitiesPublic) {
      const makePub = args.public.makeEntitiesPublic;
      let extAllow: string[] = [];
      if (makePub === "all" || makePub === "*") {
        extAllow = extensionsNormalized
          .map((e: any) => String(e.header))
          .filter((h: string) => isApprovedExtensionHeader(h));
      } else if (Array.isArray(makePub)) {
        extAllow = makePub
          .filter((h: string) => isApprovedExtensionHeader(h));
      }
      
      // Apply makeEntitiesPrivate filter
      const makePriv = args.public?.makeEntitiesPrivate;
      if (Array.isArray(makePriv)) {
        const privSet = new Set(makePriv.map((s) => String(s).toUpperCase()));
        extAllow = extAllow.filter((h) => !privSet.has(String(h).toUpperCase()));
      }
      
      for (const wanted of extAllow) {
        if (!isApprovedExtensionHeader(wanted)) continue;
        const found = extensionsNormalized.find((e: any) => String(e.header).toLowerCase() === wanted.toLowerCase());
        if (!found) throw new PublicKeyNotInAadError("PUBLIC_KEY_NOT_IN_AAD");
        json[found.header] = synthesizePaymentHeaderValue(found.payload);
      }
    }
    
    if (Object.keys(json).length > 0) {
      return { envelope, publicJson: json };
    }
  }
  
  return { envelope };
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
    x402 = primaryPayload as X402Core;
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