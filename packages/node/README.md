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
import { createHpke, generateKeyPair, buildX402Headers } from "@x402-hpke/node";

const hpke = createHpke({ namespace: "myapp" });
const { publicJwk, privateJwk } = await generateKeyPair();

const x402 = {
  invoiceId: "inv_1",
  chainId: 8453,
  tokenContract: "0x" + "a".repeat(40),
  amount: "1000",
  recipient: "0x" + "b".repeat(40),
  txHash: "0x" + "c".repeat(64),
  expiry: 9999999999,
  priceHash: "0x" + "d".repeat(64),
};

const { envelope, publicHeaders } = await hpke.seal({
  kid: "kid1",
  recipientPublicJwk: publicJwk,
  plaintext: new TextEncoder().encode("hello"),
  x402,
  public: { x402Headers: true },
});

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