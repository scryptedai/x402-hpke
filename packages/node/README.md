# @x402-hpke/node

Monorepo: https://github.com/scryptedai/x402-hpke (Node path: `packages/node`, Python path: `packages/python`).

Provider-agnostic HPKE envelope library for x402 (Node, ESM). Pinned ciphersuite for interop:
X25519 / HKDF-SHA256 / ChaCha20-Poly1305 (envelope); streaming helpers use XChaCha20-Poly1305.

## Install

Node >= 22.12

```bash
npm install @x402-hpke/node@next
```

## Quickstart

```ts
import { createHpke, generateKeyPair } from "@x402-hpke/node";

const hpke = createHpke({ namespace: "myapp" });
const { publicJwk, privateJwk } = await generateKeyPair();

// Use higher-level helpers or transport API; sidecar is private-by-default
const { envelope, publicHeaders } = await createPayment(hpke, { paymentData: { invoiceId: "inv_1" }, recipientPublicJwk: publicJwk, kid: "kid1" }, true);

const opened = await hpke.open({
  recipientPrivateJwk: privateJwk,
  envelope,
  expectedKid: "kid1",
  publicHeaders,
});
```

## Streaming (Node)

Chunk encryption helpers using XChaCha20-Poly1305:

```ts
import { sealChunkXChaCha, openChunkXChaCha } from "@x402-hpke/node";

const key = new Uint8Array(32); // derive via app contract; export API is planned
const prefix16 = new Uint8Array(16);
let seq = 0;
const ct = await sealChunkXChaCha(key, prefix16, seq++, new TextEncoder().encode("chunk"));
const pt = await openChunkXChaCha(key, prefix16, 0, ct);
```

## JWKS utilities

- `fetchJwks(url, { minTtlMs?, maxTtlMs? })`
- `setJwks(url, jwks, ttlMs?)`
- `selectJwkFromJwks(jwks, kid)`
- `createHpke(opts).fetchJwks(url?, ttl?)`: uses explicit `url` or falls back to `opts.jwksUrl`

## Notes

- AEAD is pinned to ChaCha20-Poly1305 for v1 (envelope). Streaming uses XChaCha20-Poly1305. AES-256-GCM may be offered in the future as an optional profile; suite remains pinned per version.
- ESM only.