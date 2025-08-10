import sodium from "libsodium-wrappers";
import {
  InvalidEnvelopeError,
  JwksHttpsRequiredError,
  JwksHttpError,
  JwksInvalidError,
  JwksKeyInvalidError,
  JwksKeyUseInvalidError,
  JwksKidInvalidError
} from "./errors.js";

export type OkpJwk = {
  kty: "OKP";
  crv: "X25519";
  x: string; // base64url
  d?: string; // base64url
  kid?: string;
  use?: string;
};

export type Jwks = { keys: OkpJwk[] };

const jwksCache = new Map<string, { jwks: Jwks; exp: number }>();

function b64u(bytes: Uint8Array): string {
  const s = Buffer.from(bytes).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  return s;
}

export async function generateKeyPair(): Promise<{ publicJwk: OkpJwk; privateJwk: OkpJwk }> {
  await sodium.ready;
  const kp = sodium.crypto_kx_keypair();
  const publicJwk: OkpJwk = { kty: "OKP", crv: "X25519", x: b64u(kp.publicKey) };
  const privateJwk: OkpJwk = { ...publicJwk, d: b64u(kp.privateKey) };
  return { publicJwk, privateJwk };
}

export async function generatePublicJwk(): Promise<OkpJwk> {
  const { publicJwk } = await generateKeyPair();
  return publicJwk;
}

export function selectJwkFromJwks(jwks: { keys: OkpJwk[] }, kid: string): OkpJwk | undefined {
  return (jwks.keys || []).find((k) => k.kid === kid);
}

export function jwkToPublicKeyBytes(jwk: OkpJwk): Uint8Array {
  if (jwk.kty !== "OKP" || jwk.crv !== "X25519" || !jwk.x) throw new InvalidEnvelopeError("INVALID_ENVELOPE");
  return Buffer.from(jwk.x.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

export function jwkToPrivateKeyBytes(jwk: OkpJwk): Uint8Array {
  if (!jwk.d) throw new InvalidEnvelopeError("INVALID_ENVELOPE");
  return Buffer.from(jwk.d.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function clamp(n: number, lo: number, hi: number) {
  return Math.max(lo, Math.min(hi, n));
}

function parseCacheHeaders(headers: Headers): number | undefined {
  const cc = headers.get("cache-control")?.toLowerCase();
  if (cc) {
    const m = cc.match(/(?:s-maxage|max-age)=(\d+)/);
    if (m) return parseInt(m[1], 10) * 1000;
  }
  const exp = headers.get("expires");
  if (exp) {
    const t = Date.parse(exp);
    if (!Number.isNaN(t)) return Math.max(0, t - Date.now());
  }
  return undefined;
}

export async function fetchJwks(url: string, opts?: { minTtlMs?: number; maxTtlMs?: number }): Promise<Jwks> {
  if (!url.startsWith("https://")) throw new JwksHttpsRequiredError("JWKS_HTTPS_REQUIRED");
  const now = Date.now();
  const cached = jwksCache.get(url);
  if (cached && cached.exp > now) return cached.jwks;
  const res = await fetch(url);
  if (!res.ok) throw new JwksHttpError(`JWKS_HTTP_${res.status}`);
  const jwks = (await res.json()) as Jwks;
  if (!jwks || !Array.isArray(jwks.keys)) throw new JwksInvalidError("JWKS_INVALID");
  for (const k of jwks.keys) {
    if (k.kty !== "OKP" || k.crv !== "X25519" || typeof k.x !== "string") throw new JwksKeyInvalidError("JWKS_KEY_INVALID");
    if (k.use && k.use !== "enc") throw new JwksKeyUseInvalidError("JWKS_KEY_USE_INVALID");
    if (!k.kid || typeof k.kid !== "string") throw new JwksKidInvalidError("JWKS_KID_INVALID");
  }
  let ttl = parseCacheHeaders(res.headers) ?? 300_000;
  ttl = clamp(ttl, opts?.minTtlMs ?? 60_000, opts?.maxTtlMs ?? 3_600_000);
  jwksCache.set(url, { jwks, exp: now + ttl });
  return jwks;
}

export function setJwks(url: string, jwks: Jwks, ttlMs = 300_000) {
  jwksCache.set(url, { jwks, exp: Date.now() + ttlMs });
}

export function generateJwks(keys: Array<{ jwk: OkpJwk; kid: string }>): Jwks {
  return {
    keys: keys.map(({ jwk, kid }) => ({
      ...jwk,
      kid,
      use: "enc",
      alg: "ECDH-ES"
    }))
  };
}

export function generateSingleJwks(jwk: OkpJwk, kid: string): Jwks {
  return generateJwks([{ jwk, kid }]);
}