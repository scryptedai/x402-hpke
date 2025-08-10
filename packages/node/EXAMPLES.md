# Node Examples (@x402-hpke/node)

## Server (Express)
File: `examples/express-server/server.ts`

- 402 quote response (no X-X402-* headers): returns HPKE envelope.
- Fulfill: accepts envelope (and optional sidecar headers), validates AAD equivalence, decrypts, then proceed to facilitator.

Run:
```bash
cd packages/node && npm install && npm run build && npm link
cd examples/express-server
npm init -y
npm install express body-parser tsx
npm link @x402-hpke/node
npx tsx server.ts
```

## Client (Node)
File: `examples/client-node/index.ts`

- Seals payload + AAD.
- Public sidecar: `x402Headers: true` and `appHeaderAllowlist`.

Run:
```bash
cd packages/node && npm link
cd examples/client-node
npm init -y
npm install node-fetch tsx
npm link @x402-hpke/node
npx tsx index.ts
```

## Library API Highlights

```ts
import { 
  createHpke,
  generateKeyPair,
  createRequest,
  createPayment,
  createPaymentRequired,
  createPaymentResponse
} from "@x402-hpke/node";

const hpke = createHpke({ namespace: "myapp" });
const { publicJwk, privateJwk } = await generateKeyPair();

const { envelope, publicHeaders } = await createPayment(
  hpke,
  {
    paymentData: { /* required fields */},
    recipientPublicJwk: publicJwk,
    kid: "kid-2025",
  },
  true // isPublic
);

const { plaintext, x402 } = await hpke.open({
  recipientPrivateJwk: privateJwk,
  envelope,
  expectedKid: "kid-2025",
  publicHeaders,
});
```

## Streaming (optional)

Chunk helpers in `src/streaming.ts`:
```ts
import { sealChunkXChaCha, openChunkXChaCha } from "@x402-hpke/node";
```
Use an exported 32-byte key and a 16-byte prefix with a monotonic seq to derive a 24-byte XChaCha nonce.