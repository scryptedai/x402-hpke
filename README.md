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
import { createHpke, generateKeyPair } from "@x402-hpke/node";

const hpke = createHpke({ 
  namespace: "myapp",
  // Optional: set defaults for all operations
  x402: { header: "X-Payment", payload: { invoiceId: "default" } },
  app: { traceId: "default" },
  publicEntities: "all" // or ["X-PAYMENT", "X-402-Routing"] for specific headers
});

const { publicJwk, privateJwk } = await generateKeyPair();

const x402 = {
  header: "X-Payment",
  payload: {
    invoiceId: "inv_1",
    chainId: 8453,
    tokenContract: "0x" + "a".repeat(40),
    amount: "1000",
    recipient: "0x" + "b".repeat(40),
    txHash: "0x" + "c".repeat(64),
    expiry: 9999999999,
    priceHash: "0x" + "d".repeat(64),
  }
};

const payload = new TextEncoder().encode("hello");
const { envelope, publicHeaders } = await hpke.seal({
  kid: "kid1",
  recipientPublicJwk: publicJwk,
  plaintext: payload,
  x402,
  app: { traceId: "req_123" },
  public: { 
    makeEntitiesPublic: "all", // or ["X-PAYMENT", "X-402-Routing"]
    makeEntitiesPrivate: ["traceId"], // optionally hide specific entities
    as: "headers" // or "json"
  },
  httpResponseCode: 200 // controls sidecar behavior (402 = no payment headers)
});

const opened = await hpke.open({ 
  recipientPrivateJwk: privateJwk, 
  envelope, 
  expectedKid: "kid1", 
  publicHeaders 
});
```

## Quickstart (Python)

```python
from x402_hpke import create_hpke
from x402_hpke.keys import generate_keypair

hpke = create_hpke(
    namespace="myapp",
    # Optional: set defaults for all operations
    x402={"header": "X-Payment", "payload": {"invoiceId": "default"}},
    app={"traceId": "default"},
    public_entities="all"  # or ["X-PAYMENT", "X-402-Routing"] for specific headers
)

PUB, PRIV = generate_keypair()

x402 = {
    "header": "X-Payment",
    "payload": {
        "invoiceId": "inv_1",
        "chainId": 8453,
        "tokenContract": "0x" + "a"*40,
        "amount": "1000",
        "recipient": "0x" + "b"*40,
        "txHash": "0x" + "c"*64,
        "expiry": 9999999999,
        "priceHash": "0x" + "d"*64,
    }
}

payload = b"hello"

env, headers = hpke.seal(
    kid="kid1", 
    recipient_public_jwk=PUB, 
    plaintext=payload, 
    x402=x402, 
    app={"traceId": "req_123"},
    public={
        "makeEntitiesPublic": "all",  # or ["X-PAYMENT", "X-402-Routing"]
        "makeEntitiesPrivate": ["traceId"],  # optionally hide specific entities
        "as": "headers"  # or "json"
    },
    http_response_code=200  # controls sidecar behavior (402 = no payment headers)
)

pt, x, app = hpke.open(
    recipient_private_jwk=PRIV, 
    envelope=env, 
    expected_kid="kid1", 
    public_headers=headers
)
```

## Core x402 Object Structure

The x402 core object must include:
- `header`: "X-Payment" or "X-Payment-Response" (case-insensitive)
- `payload`: a non-empty object containing payment details

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

- Node: `fetchJwks(url)`, `setJwks(url, jwks)`, `selectJwkFromJwks(jwks, kid)`
- Python: `fetch_jwks(url)`, `set_jwks(url, jwks)`, `select_jwk(kid, jwks, url)`
- HTTPS-only, basic caching using Cache-Control/Expires, and kid-based selection.

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