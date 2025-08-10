# x402-hpke

Provider-agnostic HPKE envelope library for x402 — Node (TypeScript) and Python (Poetry). Canonical AAD with x402 fields, optional public sidecar (headers/JSON) for legacy middleware, and deterministic interop.

- Repository: `https://github.com/scryptedai/x402-hpke`
- Monorepo layout:
  - Node (TypeScript): `packages/node`
  - Python (Poetry): `packages/python`
- Packages:
  - Node: `@x402-hpke/node`
  - Python: `x402-hpke`

Current versions
- Python: `0.1.0a1` (alpha, prerelease)
- Node: `0.1.0-alpha.1` (alpha, prerelease)
- Pinned ciphersuite (v1): X25519 / HKDF-SHA256 / ChaCha20-Poly1305 (envelope). Streaming uses exported key + XChaCha20-Poly1305.
- AAD is the single source of truth for all x402 + app metadata. Payload is opaque by default.
- Optional public sidecar is a projection of AAD; server enforces byte-for-byte equivalence.

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
const { envelope, publicJsonBody } = await createRequest(
  hpke,
  {
    requestData: { action: "getUserProfile", userId: "user-123" },
    recipientPublicJwk: publicJwk,
    kid: "client-key-1",
  },
  true // isPublic
);

const { plaintext, request } = await hpke.open({ 
  recipientPrivateJwk: privateJwk, 
  envelope,
  expectedKid: "server-key-1"
});

// Generic response
const { envelope: responseEnvelope, publicJsonBody: responsePublicBody } = await createResponse(
  hpke,
  {
    responseData: { status: "ok", data: { a: 1 } },
    recipientPublicJwk: publicJwk,
    kid: "server-key-1",
    httpResponseCode: 200,
  },
  true // isPublic
);

// Payment request
const { envelope: paymentEnvelope, publicHeaders } = await createPayment(
  hpke,
  {
    paymentData: { /* ...EVM payment details... */ },
    recipientPublicJwk: publicJwk,
    kid: "client-key-1",
  },
  true // isPublic
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

# Generic request
env, body = create_request(
    hpke,
    request_data={"action": "getUserProfile", "userId": "user-123"},
    recipient_public_jwk=PUB,
    kid="client-key-1",
    is_public=True,
)

pt, req, _ = hpke.open(
    recipient_private_jwk=PRIV, 
    envelope=env,
    expected_kid="server-key-1"
)

# Generic response
env, body = create_response(
    hpke,
    response_data={"status": "ok", "data": {"a": 1}},
    recipient_public_jwk=PUB,
    kid="server-key-1",
    http_response_code=200,
    is_public=True,
)

# Payment request
env, headers = create_payment(
    hpke,
    payment_data={ /* ...EVM payment details... */ },
    recipient_public_jwk=PUB,
    kid="client-key-1",
    is_public=True,
)
```

## Core Concepts

The `x402-hpke` library provides a flexible framework for secure, authenticated messaging. The `seal` method is the heart of the library, accepting one of three mutually exclusive payload types:

- **`request`**: For generic client-to-server messages.
- **`response`**: For generic server-to-client messages.
- **`x402`**: For specialized `402` payment protocol messages.

### Typical 402 payment flows

Most production integrations center on the x402 flows. At a high level:

- Price quote (server → client): server returns a 402 Payment Required using `createPaymentRequired` (x402 header is empty, body carries quote details)
- Client payment (client → server): client submits an X-Payment using `createPayment`
- Settlement/receipt (server → client): server returns X-Payment-Response using `createPaymentResponse`

You will still use the generic surfaces when needed:
- `createRequest` to initiate a non-payment request (e.g., ask for a price or send opaque app payload)
- `createResponse` to return non-402 responses (e.g., 200/4xx error details that are not part of x402)

### Generic Request/Response

Request/response are utility surfaces used to initiate a quote/request and to handle non-402 responses. They provide a simple API for sealing opaque app data when you are not sending an x402 header.

```typescript
// Seal a request
const { envelope, publicJsonBody } = await hpke.seal({
  request: { action: "getData", params: { id: 123 } },
  // ... other seal params
  public: { makeEntitiesPublic: ["request"] }
});

// The 'publicJsonBody' will be the raw 'request' object,
// which you can send as the body of your HTTP request.
```

### Payment Protocol (`x402`)

For `402` payment flows, the `x402` payload provides a structured way to handle `X-Payment` and `X-Payment-Response` headers. The library enforces the correct usage based on the `httpResponseCode`.

```typescript
// Seal an X-Payment header
const { envelope, publicHeaders } = await hpke.seal({
  x402: {
    header: "X-Payment",
    payload: { /* ... */ }
  },
  // ... other seal params
  public: { makeEntitiesPublic: ["X-Payment"] }
});
// 'publicHeaders' will contain the 'X-Payment' header
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

- **Default**: No transport headers are emitted; all metadata is bound inside AAD
- **Optional**: Use `public` in `seal()` to emit sidecars:
  - `makeEntitiesPublic: "all"` → emits all available entities (core payment + approved extensions)
  - `makeEntitiesPublic: ["X-PAYMENT", "X-402-Routing"]` → emits specific entities
  - `makeEntitiesPrivate: ["traceId"]` → subtracts entities from the public set
  - `as: "headers"` (default) or `"json"` → controls sidecar format

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

## Constructor Defaults

Set defaults at HPKE creation time for consistent behavior across all operations:

```ts
const hpke = createHpke({
  namespace: "myapp",
  x402: { header: "X-Payment", payload: { /* default payment */ } },
  app: { traceId: "default", model: "gpt-4" },
  publicEntities: "all" // or specific list
});
```

These defaults are merged with per-call values, with per-call taking precedence.

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
