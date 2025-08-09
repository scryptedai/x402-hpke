# JWKS (JSON Web Key Set)

- Keys are OKP X25519 JWKs with `kty=OKP`, `crv=X25519`, `x` (and `d` for private). Optional `use` should be `enc`.
- `kid` is required and used for recipient selection.
- HTTPS-only fetch; responses must be JSON with a `keys` array.
- Caching: honor `Cache-Control` `max-age`/`s-maxage` and `Expires` headers; clamp TTL to safe bounds.
- Selection: choose key where `kid` matches exactly; error if not found.

Language APIs
- Node: `fetchJwks(url, { minTtlMs?, maxTtlMs? })`, `setJwks(url, jwks, ttlMs?)`, `selectJwkFromJwks(jwks, kid)`
- Python: `fetch_jwks(url, min_ttl?, max_ttl?)`, `set_jwks(url, jwks, ttl?)`, `select_jwk(kid, jwks=None, url=None)`

No-JWKS client keys (best practices)
- If a client has no HTTPS JWKS, it may embed a raw OKP X25519 public JWK in AAD (`replyToJwk`).
- Libraries expose helpers to generate a valid public JWK:
  - Node: `generatePublicJwk()`
  - Python: `generate_public_jwk()`
- Rotation guidance:
  - Rotate client keys periodically or per session; at minimum rotate on compromise or crypto policy updates.
  - Use `replyToKid` consistently when using JWKS to identify the active client key.
  - Prefer short‑lived `replyToJwk` pairs for high‑risk contexts; include `requestId/nonce` in AAD and maintain a dedupe window on the receiver.

Node `createHpke().fetchJwks(url?, ttl?)` behavior
- Preferred: pass an explicit `url`.
- Fallback: if omitted, uses `createHpke({ jwksUrl })` provided at construction.
- Rationale: keeps call sites concise where a single JWKS endpoint is standard while avoiding hidden global config.