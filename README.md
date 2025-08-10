# x402-hpke
Secure Transport for x402 (End-to-End Encryption)

Provider-agnostic HPKE envelope library for x402 - Node (TypeScript) and Python (Poetry). Canonical AAD built from a unified transport model, optional sidecar public projection that is private-by-default, and deterministic interop.

- Repository: `https://github.com/scryptedai/x402-hpke`
- Monorepo layout:
  - Node (TypeScript): `packages/node`
  - Python (Poetry): `packages/python`
- Packages:
  - Node: `@x402-hpke/node`
  - Python: `x402-hpke`

Current versions
- Python: `0.2.0a0` (alpha, prerelease)
- Node: `0.2.0-alpha.0` (alpha, prerelease)
- Pinned ciphersuite (v1): X25519 / HKDF-SHA256 / ChaCha20-Poly1305 (envelope). Streaming uses exported key + XChaCha20-Poly1305.
- AAD is the single source of truth for all x402 + app metadata. Sidecar is disabled by default.
- Optional sidecar is a projection of AAD; server enforces byte-for-byte equivalence.

License: MIT © 2025 Tim Cotten <tcotten@scrypted.ai>, Scrypted Inc.

## Install

Node (>= 22.12):
```bash
cd packages/node
npm install
npm run build
```

Python (>= 3.12):
```bash
cd packages/python
poetry install
# prerelease is available on PyPI
pip install --pre x402-hpke
```

## Monorepo build/test (from repo root)

Use Poetry scripts to build and test both packages from the root:

```bash
# Build Python env and Node dist
poetry run build-all

# Run Node tests only
poetry run test-node

# Run Python tests only
poetry run test-python

# Run Node tests then Python tests
poetry run test-all

# CI-style: prepare Python, build Node, run Node tests, then Python tests
poetry run ci
```

## Quickstart (Node)

```ts
import { 
  createHpke,
  generateKeyPair,
  createRequest,
  createResponse,
  createPayment,
  createPaymentRequired,
  createPaymentResponse
} from "@x402-hpke/node";

const hpke = createHpke({ 
  namespace: "myapp",
});

const { publicJwk, privateJwk } = await generateKeyPair();

// Generic request
const { envelope } = await createRequest(
  hpke,
  {
    requestData: { action: "getUserProfile", userId: "user-123" },
    recipientPublicJwk: publicJwk,
    kid: "client-key-1",
  },
  false // private by default
);

const { plaintext, body } = await hpke.open({ 
  recipientPrivateJwk: privateJwk, 
  envelope,
  expectedKid: "server-key-1"
});
// body == { action: "getUserProfile", userId: "user-123" }

// Generic response
const { envelope: responseEnvelope } = await createResponse(
  hpke,
  {
    responseData: { status: "ok", data: { a: 1 } },
    recipientPublicJwk: publicJwk,
    kid: "server-key-1",
    httpResponseCode: 200,
  },
  false // private by default
);

// Payment request (public sidecar optional)
const { envelope: paymentEnvelope, publicHeaders } = await createPayment(
  hpke,
  {
    paymentData: { /* ...EVM payment details... */ },
    recipientPublicJwk: publicJwk,
    kid: "client-key-1",
  },
  true // request explicit sidecar
);
```

## Quickstart (Python)

```python
from x402_hpke import (
    create_hpke,
    create_request,
    create_response,
    create_payment,
    create_payment_required,
    create_payment_response,
)
from x402_hpke.keys import generate_keypair

hpke = create_hpke(namespace="myapp")

PUB, PRIV = generate_keypair()

# Generic request (private by default)
env, _ = create_request(
    hpke,
    request_data={"action": "getUserProfile", "userId": "user-123"},
    recipient_public_jwk=PUB,
    kid="client-key-1",
    is_public=False,
)

pt, body, headers = hpke.open(
    recipient_private_jwk=PRIV, 
    envelope=env,
    expected_kid="server-key-1"
)
assert body == {"action": "getUserProfile", "userId": "user-123"}

# Generic response (private by default)
env, _ = create_response(
    hpke,
    response_data={"status": "ok", "data": {"a": 1}},
    recipient_public_jwk=PUB,
    kid="server-key-1",
    http_response_code=200,
    is_public=False,
)

# Payment request (optional public sidecar)
env, headers = create_payment(
    hpke,
    payment_data={ "invoiceId": "inv_1" },
    recipient_public_jwk=PUB,
    kid="client-key-1",
    is_public=True,
)
```

## Unified Transport and Helpers (recommended)

Use the helpers (`createPayment`, `createPaymentResponse`, `createPaymentRequired`, `createRequest`, `createResponse`) for almost all cases. They construct an internal `x402SecureTransport` for you and call `seal()` with the right shape, so you don’t need to reason about headers vs body or status codes.

High-level flows typically look like:
- Quote (server → client): `createPaymentRequired` (body contains quote data; no core x402 headers exposed in sidecar for 402)
- Client payment (client → server): `createPayment` (core header `X-PAYMENT`)
- Receipt (server → client): `createPaymentResponse` (core header `X-PAYMENT-RESPONSE`, auto HTTP 200)
- Generic app data: `createRequest` / `createResponse`

### What `x402SecureTransport` does (auto-mapping/routing)
The unified transport model enforces validation and maps your content to headers/body based on type:
- PAYMENT: header = `X-PAYMENT`, value = your content; body = `{}`; `httpResponseCode` not allowed
- PAYMENT_RESPONSE: header = `X-PAYMENT-RESPONSE`, value = your content; body = `{}`; `httpResponseCode` auto-set to 200
- PAYMENT_REQUIRED: header = `""` (suppressed), body = your content; `httpResponseCode` auto-set to 402
- OTHER_REQUEST: header = none, body = your content; `httpResponseCode` not allowed
- OTHER_RESPONSE: header = none, body = your content; `httpResponseCode` required and must not be 402

Headers and body are bound into AAD with header names verbatim and deep-canonicalized values for deterministic interop. Sidecar is private-by-default and only contains entities explicitly selected via `makeEntitiesPublic`.

### Low-level (optional)
If you need maximum control, you can construct the transport directly and call `seal`:

```ts
import { x402SecureTransport } from "@x402-hpke/node";

const t = new x402SecureTransport("PAYMENT", { payload: { invoiceId: "inv_123" } });
const { envelope, publicHeaders } = await hpke.seal({
  kid: "kid1",
  recipientPublicJwk: publicJwk,
  transport: t,
  makeEntitiesPublic: ["X-PAYMENT"], // optional
});
```

## Core x402 Object Structure

The x402 core object must include:
- `header`: "X-Payment", "X-Payment-Response", or "" (empty for confidential requests)
- `payload`: a non-empty object containing payment details or confidential data

### Header Usage Rules

- **"X-Payment"**: Client requests with payment (no httpResponseCode)
- **"X-Payment-Response"**: Server responses with payment receipt (requires httpResponseCode: 200)
- **"" (empty)**: Confidential requests/responses (402 or other status codes)

### HTTP Response Code Validation

- **`request` payloads**: `httpResponseCode` is not allowed.
- **`response` payloads**: `httpResponseCode` is required.
- **`x402` payloads**:
  - **`X-Payment`**: `httpResponseCode` is not allowed.
  - **`X-Payment-Response`**: `httpResponseCode` is required and must be `200`.
  - **`header: ""`**: `httpResponseCode` is required and must be `402`.

Example x402 object:
```json
{
  "header": "X-Payment",
  "payload": {
    "x402Version": 1,
    "scheme": "exact",
    "network": "base-sepolia",
    "payload": {
      "signature": "0x2d6a7588d6acca505cbf0d9a4a227e0c52c6c34008c8e8986a1283259764173608a2ce6496642e377d6da8dbbf5836e9bd15092f9ecab05ded3d6293af148b571c",
      "authorization": {
        "from": "0x857b06519E91e3A54538791bDbb0E22373e36b66",
        "to": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
        "value": "10000",
        "validAfter": "1740672089",
        "validBefore": "1740672154",
        "nonce": "0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480"
      }
    }
  }
}
```

## Transport Sidecar (Headers/JSON)

- **Default**: Nothing is exposed; all metadata is AAD-bound.
- **Optional**: Provide `makeEntitiesPublic: "all" | "*" | string[]` (via helpers or direct `seal`) to project selected entities:
  - For headers, you’ll get `publicHeaders` with values as compact JSON strings
  - For body keys, you’ll get `publicBody` with selected keys

### HTTP Response Code Behavior

- **402 responses**: Never emit X-PAYMENT headers in sidecar (only approved extensions)
- **Other responses**: Can emit both payment headers and approved extensions
- **Client requests**: Can emit X-PAYMENT headers for payment verification

### Approved Extension Headers (v1)

- `X-402-Routing` — service routing and priority
- `X-402-Limits` — rate limiting and quotas  
- `X-402-Acceptable` — content labels and jurisdiction info
- `X-402-Metadata` — arbitrary key-value metadata
- `X-402-Security` — security requirements and key management

Server must rebuild AAD from sidecar and require byte-for-byte equality. Mismatch → `400 AAD_MISMATCH`.

## Notes
Helpers are the canonical way to use this library. They create the transport, enforce validation, and keep everything private unless you explicitly request sidecar exposure.

## JWKS Utilities

- Node: `fetchJwks(url)`, `setJwks(url, jwks)`, `selectJwkFromJwks(jwks, kid)`, `generateJwks(keys)`, `generateSingleJwks(jwk, kid)`
- Python: `fetch_jwks(url)`, `set_jwks(url, jwks)`, `select_jwk(kid, jwks, url)`, `generate_jwks(keys)`, `generate_single_jwks(jwk, kid)`
- HTTPS-only, basic caching using Cache-Control/Expires, and kid-based selection.
- JWKS generation utilities for creating inline JWKS in X-402-Security extensions.

## X-402-Security Extension

The `X-402-Security` extension allows clients and servers to negotiate security requirements:

```typescript
// Example X-402-Security payload
{
  jwksUrl: "https://example.com/.well-known/jwks.json",
  // OR inline JWKS
  jwks: generateJwks([{ jwk: publicKey, kid: "key1" }]),
  minKeyStrength: 256,
  allowedSuites: ["X25519", "P-256"]
}
```

This enables:
- **Key Discovery**: Share JWKS endpoints or inline keys
- **Security Negotiation**: Specify minimum key strength and allowed algorithms
- **Client Key Rotation**: Provide fresh keys for each request

## Streaming (XChaCha20-Poly1305)

Export a symmetric key from the HPKE context and use XChaCha20-Poly1305 per-chunk:

```ts
// Node
import { sealChunkXChaCha, openChunkXChaCha, XChaChaStreamLimiter } from "@x402-hpke/node";

// Basic chunk operations
const ct = await sealChunkXChaCha(key, prefix16, seq, chunk, aad?);
const pt = await openChunkXChaCha(key, prefix16, seq, ct, aad?);

// Limit-enforcing wrapper
const limiter = new XChaChaStreamLimiter(key, prefix16, { 
  maxChunks: 1000, 
  maxBytes: 1000000 
});
const ct = await limiter.seal(seq, chunk, aad?);
const pt = await limiter.open(seq, ct, aad?);
```

```python
# Python
from x402_hpke import seal_chunk_xchacha, open_chunk_xchacha, XChaChaStreamLimiter

# Basic chunk operations
ct = seal_chunk_xchacha(key, prefix16, seq, chunk, aad=None)
pt = open_chunk_xchacha(key, prefix16, seq, ct, aad=None)

# Limit-enforcing wrapper
limiter = XChaChaStreamLimiter(key, prefix16, max_chunks=1000, max_bytes=1000000)
ct = limiter.seal(seq, chunk, aad=None)
pt = limiter.open(seq, ct, aad=None)
```

- Nonce: 24 bytes = `prefix(16) || le64(seq)`
- Each chunk: `{ seq, ct }` with AEAD tag included
- Reject out-of-order or duplicate seq
- Enforce limits before large seq windows

## Examples

- Express server: `examples/express-server/server.ts` (402 quote + fulfill)
- FastAPI server: `examples/fastapi-server/app.py`
- Clients: `examples/client-node`, `examples/client-python`

Notes for running examples:
- Node examples import `@x402-hpke/node`. For local dev, either publish or run `npm link`:
  ```bash
  cd packages/node && npm install && npm run build && npm link
  cd examples/express-server && npm init -y && npm install express body-parser tsx && npm link @x402-hpke/node && npx tsx server.ts
  cd examples/client-node && npm init -y && npm install node-fetch tsx && npm link @x402-hpke/node && npx tsx index.ts
  ```
- Python examples:
  ```bash
  cd packages/python && poetry install
  poetry run uvicorn examples.fastapi-server.app:app --reload
  poetry run python examples/client-python/client.py
  ```

## Tests

- Node:
  ```bash
  cd packages/node
  npm install
  npm test
  ```
- Python:
  ```bash
  cd packages/python
  poetry install
  poetry run pytest -q
  ```
- Interop: Node suite includes Node→Python and Python→Node tests (invokes Poetry).
 - From root, you can also run:
   ```bash
   poetry run test-all
   ```

## CI

- See `.github/workflows/ci.yml`. Matrix for Node and Python. Interop test step can be added to run in CI.

## Spec & docs

- `docs/SPEC.md` — spec highlights and updates
- `docs/AAD.md` — canonicalization rules
- `docs/JWKS.md` — key publishing rotation and caching
- `docs/HEADERS.md` — sidecar and namespacing rules
- `docs/STREAMING.md` — streaming design
 - `docs/THREAT_MODEL.md` — goals, non-goals, attacker model, mitigations, replay guidance

## Acknowledgements

This code library was developed with the assistance of large language models (LLMs), which served as interactive tools to accelerate the engineering workflow. Their specific contributions included conceptualization, code generation, debugging, and documentation. The primary models consulted were OpenAI's ChatGPT and Anthropic's Claude. While these tools were integral to the development process, the architecture decisions, implementation oversight, and all final conclusions are the sole work of the human author.
