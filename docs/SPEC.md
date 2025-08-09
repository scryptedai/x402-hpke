# Technical Design — x402-hpke (Hybrid Public Key Encryption, HPKE; pinned for interop)

- Repository: https://github.com/scryptedai/x402-hpke
- Monorepo paths: Node (TypeScript) at `packages/node`, Python at `packages/python`.

- Ciphersuite (v1, pinned for maximum interop):
  - KEM (Key Encapsulation Mechanism): X25519
  - KDF (Key Derivation Function): HKDF-SHA256
  - AEAD (Authenticated Encryption with Associated Data, envelope): ChaCha20-Poly1305 (96-bit nonce, libsodium `*_ietf`)
  - Suite ID: `X25519-HKDF-SHA256-CHACHA20POLY1305`
  - Envelope MAY include `suite` field; APIs expose `hpke.suite` and `hpke.version`.
- AAD (Additional Authenticated Data) is canonical; payload is opaque. Public sidecar is a projection of AAD; mismatch rejected.
- JWKS (JSON Web Key Set): HTTPS-only fetch with Cache-Control/Expires; selection by `kid`.
- Interop: Node seals ↔ Python opens and vice versa. Cross-language tests included.

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

## API Interface

### HPKE Creation

```typescript
// Node
const hpke = createHpke({
  namespace: "myapp",
  // Optional: set defaults for all operations
  x402: { header: "X-Payment", payload: { /* default payment */ } },
  app: { traceId: "default", model: "gpt-4" },
  publicEntities: "all" // or ["X-PAYMENT", "X-402-Routing"] for specific headers
});
```

```python
# Python
hpke = create_hpke(
    namespace="myapp",
    # Optional: set defaults for all operations
    x402={"header": "X-Payment", "payload": {"/* default payment */"}},
    app={"traceId": "default", "model": "gpt-4"},
    public_entities="all"  # or ["X-PAYMENT", "X-402-Routing"] for specific headers
)
```

### Sidecar Generation

Use `public` in `seal()` to control sidecar behavior:

- `makeEntitiesPublic: "all"` → emits all available entities (core payment + approved extensions)
- `makeEntitiesPublic: ["X-PAYMENT", "X-402-Routing"]` → emits specific entities
- `makeEntitiesPrivate: ["traceId"]` → subtracts entities from the public set
- `as: "headers"` (default) or `"json"` → controls sidecar format

### HTTP Response Code Behavior

The `httpResponseCode` parameter controls sidecar behavior:

- **402 responses**: Never emit X-PAYMENT headers in sidecar (only approved extensions)
- **Other responses**: Can emit both payment headers and approved extensions
- **Client requests**: Can emit X-PAYMENT headers for payment verification

## Extensions (optional)

- Approved extension headers (v1): `X-402-Routing`, `X-402-Limits`, `X-402-Acceptable`, `X-402-Metadata`.
- Place as objects in `app.extensions`: each `{ header, payload, ... }` is canonicalized and AAD-bound; optionally uplift via `public.makeEntitiesPublic`.

## Media type

- Provisional media type for content negotiation: `application/x402-envelope+json`.

## Notes:

- We use ChaCha20-Poly1305 for the envelope to align with RFC 9180 (96-bit nonce).
- Streaming helpers use XChaCha20-Poly1305 for chunking (separate key/nonce prefix), see STREAMING.md.

## Suite mapping (informative)

- v1 `X25519-HKDF-SHA256-CHACHA20POLY1305`:
  - KEM = X25519
  - KDF = HKDF-SHA256
  - AEAD (envelope) = ChaCha20-Poly1305 (IETF 96-bit nonce)
  - Streaming AEAD = XChaCha20-Poly1305
  - Envelope MAY include `suite`; APIs expose `hpke.suite` and `hpke.version`.
  - Future: An AES-256-GCM profile may be added for FIPS-leaning environments under a distinct suite ID.

## HKDF info binding (normative)

- Seal: `"x402-hpke:v1|KDF=<KDF>|AEAD=<AEAD>|ns=<NS>|enc=<ENC>|pkR=<PKR>"`
- Open: `"x402-hpke:v1|KDF=<KDF>|AEAD=<AEAD>|ns=<NS>|enc=<ENC>|pkR=<PKR>"`
  - `<ENC>` and `<PKR>` are base64url (no padding)

## Equality checks (normative)

- Implementations MUST use constant-time comparisons when checking AAD equivalence or tags (e.g., `timingSafeEqual` in Node, `hmac.compare_digest` in Python).