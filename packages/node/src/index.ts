export type Algorithms = {
  kem: "X25519";
  kdf: "HKDF-SHA256";
  aead: "CHACHA20-POLY1305" | "AES-256-GCM";
};

export type CreateHpkeOptions = {
  namespace: string; // not "x402"
  kem?: Algorithms["kem"];
  kdf?: Algorithms["kdf"];
  aead?: Algorithms["aead"];
  jwksUrl?: string;
};

import { seal, open } from "./envelope.js";
import { generateKeyPair, selectJwkFromJwks, fetchJwks, setJwks, type Jwks } from "./keys.js";
export { canonicalAad, buildCanonicalAad, validateX402 } from "./aad.js";
export { generateKeyPair, selectJwkFromJwks } from "./keys.js";
export { buildX402Headers } from "./headers.js";
export { sealChunkXChaCha, openChunkXChaCha } from "./streaming.js";

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
    seal: (args: Parameters<typeof seal>[0]) => seal({ ...args, namespace: ns, kem, kdf, aead }),
    open: (args: Parameters<typeof open>[0]) => open({ ...args, namespace: ns, kem, kdf, aead }),
    canonicalAad: (x402: any, app?: any) => canonicalAad(ns, x402, app),
    generateKeyPair,
    selectJwkFromJwks,
    buildX402Headers: (x: any) => buildX402Headers(x),
    async fetchJwks(url?: string, opts?: { minTtlMs?: number; maxTtlMs?: number }): Promise<Jwks> {
      const u = url ?? opts?.["url"] ?? (opts as any)?.url; // tolerate legacy
      const final = u ?? (opts as any)?.jwksUrl ?? (opts as any)?.url ?? (opts as any) ?? undefined;
      return fetchJwks(final ?? (opts as any)?.url ?? "");
    },
    setJwks,
  };
}