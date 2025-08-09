export type Algorithms = {
  kem: "X25519";
  kdf: "HKDF-SHA256";
  // Envelope AEAD is pinned to ChaCha20-Poly1305 (RFC 9180) for v1
  aead: "CHACHA20-POLY1305";
};

export type CreateHpkeOptions = {
  namespace: string; // not "x402"
  kem?: Algorithms["kem"];
  kdf?: Algorithms["kdf"];
  aead?: Algorithms["aead"];
  jwksUrl?: string;
};

import { seal, open } from "./envelope.js";
import { generateKeyPair, selectJwkFromJwks, fetchJwks, setJwks, type Jwks, generatePublicJwk } from "./keys.js";
import { canonicalAad, buildCanonicalAad, validateX402 } from "./aad.js";
import { buildX402Headers } from "./headers.js";
export { canonicalAad, buildCanonicalAad, validateX402 } from "./aad.js";
export { generateKeyPair, selectJwkFromJwks, generatePublicJwk } from "./keys.js";
export { buildX402Headers } from "./headers.js";
export { sealChunkXChaCha, openChunkXChaCha } from "./streaming.js";
export * as X402Errors from "./errors.js";

export const X402_HPKE_VERSION = "v1" as const;
export const X402_HPKE_SUITE = "X25519-HKDF-SHA256-CHACHA20POLY1305" as const;

export function createHpke(opts: CreateHpkeOptions) {
  const ns = opts.namespace;
  if (!ns || ns.toLowerCase() === "x402") {
    throw Object.assign(new Error("NS_FORBIDDEN"), { code: 400 });
  }
  const kem = opts.kem ?? "X25519";
  const kdf = opts.kdf ?? "HKDF-SHA256";
  const aead = opts.aead ?? "CHACHA20-POLY1305";
  return {
    namespace: ns,
    kem,
    kdf,
    aead,
    version: X402_HPKE_VERSION,
    suite: X402_HPKE_SUITE,
    seal: (args: Parameters<typeof seal>[0]) => seal({ ...args, namespace: ns, kem, kdf, aead }),
    open: (args: Parameters<typeof open>[0]) => open({ ...args, namespace: ns, kem, kdf, aead }),
    canonicalAad: (x402: any, app?: any) => canonicalAad(ns, x402, app),
    generateKeyPair,
    generatePublicJwk,
    selectJwkFromJwks,
    buildX402Headers: (x: any) => buildX402Headers(x),
    // Simplified JWKS fetch: prefer explicit url, fall back to createHpke(opts).jwksUrl
    async fetchJwks(url?: string, ttl?: { minTtlMs?: number; maxTtlMs?: number }): Promise<Jwks> {
      const effectiveUrl = url ?? opts.jwksUrl;
      if (!effectiveUrl) throw new Error("JWKS_URL_REQUIRED");
      return fetchJwks(effectiveUrl, ttl);
    },
    setJwks,
  };
}