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
- Node: `0.1.0` (preview)
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

const payload = new TextEncoder().encode("hello");
const { envelope, publicHeaders } = await hpke.seal({
  kid: "kid1",
  recipientPublicJwk: publicJwk,
  plaintext: payload,
  x402,
  public: { x402Headers: true, appHeaderAllowlist: ["traceId"], as: "headers" },
});

const opened = await hpke.open({ recipientPrivateJwk: privateJwk, envelope, expectedKid: "kid1", publicHeaders });
```

## Quickstart (Python)

```python
from x402_hpke import create_hpke
from x402_hpke.keys import generate_keypair

hpke = create_hpke(namespace="myapp")
PUB, PRIV = generate_keypair()

x402 = {
    "invoiceId": "inv_1",
    "chainId": 8453,
    "tokenContract": "0x" + "a"*40,
    "amount": "1000",
    "recipient": "0x" + "b"*40,
    "txHash": "0x" + "c"*64,
    "expiry": 9999999999,
    "priceHash": "0x" + "d"*64,
}

payload = b"hello"

env, headers = hpke.seal(kid="kid1", recipient_public_jwk=PUB, plaintext=payload, x402=x402, public={"x402Headers": True})
pt, x, app = hpke.open(recipient_private_jwk=PRIV, envelope=env, expected_kid="kid1", public_headers=headers)
```

## Public sidecar (headers/JSON)
- Default: no `X-X402-*` headers; all x402 fields are inside AAD.
- Optional: `public` in `seal()` produces either `publicHeaders` or `publicJson` with a projection of AAD.
- Server must rebuild AAD from sidecar and require byte-for-byte equality. Mismatch → `400 AAD_MISMATCH`.

See `docs/HEADERS.md` for exact maps and examples.

## JWKS utilities
- Node: `fetchJwks(url)`, `setJwks(url, jwks)`, `selectJwkFromJwks(jwks, kid)`
- Python: `fetch_jwks(url)`, `set_jwks(url, jwks)`, `select_jwk(kid, jwks, url)`
- HTTPS-only, basic caching using Cache-Control/Expires, and kid-based selection.

## Streaming (optional)
- Export a symmetric key from the HPKE context (design in `docs/STREAMING.md`) and use `XChaCha20-Poly1305` per-chunk with 24-byte nonce = `prefix(16) || le64(seq)`.
- In v1, Node exports helpers: `sealChunkXChaCha`, `openChunkXChaCha` for chunk operations.

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
```
This code library was developed with the assistance of large language models (LLMs), which served as interactive tools to accelerate the engineering workflow. Their specific contributions included conceptualization, code generation, debugging, and documentation. The primary models consulted were OpenAI’s ChatGPT and Anthropic’s Claude. While these tools were integral to the development process, the architecture decisions, implementation oversight, and all final conclusions are the sole work of the human author.
```