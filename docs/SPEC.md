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
- `header`: "X-Payment", "X-Payment-Response", or "" (empty for confidential requests)
- `payload`: a non-empty object containing payment details or confidential data

### Header Usage Rules

- **"X-Payment"**: Client requests with payment (no httpResponseCode)
- **"X-Payment-Response"**: Server responses with payment receipt (requires httpResponseCode: 200)
- **"" (empty)**: Confidential requests/responses (402 or other status codes)

### HTTP Response Code Validation

- **402 responses**: `x402.header` MUST be `""` (empty) - never "X-Payment" or "X-Payment-Response"
- **X-Payment**: No `httpResponseCode` should be set (client requests)
- **X-Payment-Response**: Requires `httpResponseCode: 200`

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
  publicEntities: "all" // or ["request", "X-402-Routing"] for specific entities
});
```

```python
# Python
hpke = create_hpke(
    namespace="myapp",
    # Optional: set defaults for all operations
    public_entities="all"  # or ["request", "X-402-Routing"] for specific entities
)
```

### Sealing Payloads

The `seal` method accepts one of three mutually exclusive payload types:

- **`request`**: For generic client-to-server messages.
- **`response`**: For generic server-to-client messages.
- **`x402`**: For specialized `402` payment protocol messages.

#### Generic Request/Response

```typescript
// Seal a request
const { envelope, publicJsonBody } = await hpke.seal({
  request: { action: "getData", params: { id: 123 } },
  // ... other seal params
  public: { makeEntitiesPublic: ["request"] }
});
```

If `makeEntitiesPublic` includes `"request"` or `"response"`, the corresponding object will be returned as a JSON body in the `publicJsonBody` field.

#### Payment Protocol (`x402`)

The `x402` payload is used for handling `X-Payment` and `X-Payment-Response` headers.

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
```

### Sidecar Generation

Use `public` in `seal()` to control sidecar behavior:

- `makeEntitiesPublic: "all"` → emits all available entities (core payment + approved extensions)
- `makeEntitiesPublic: ["X-PAYMENT", "X-402-Routing"]` → emits specific entities
- `makeEntitiesPrivate: ["traceId"]` → subtracts entities from the public set
- `as: "headers"` (default) or `"json"` → controls sidecar format

### HTTP Response Code Behavior

The `httpResponseCode` parameter controls sidecar behavior and enforces header validation:

- **402 responses**: Never emit X-PAYMENT headers in sidecar (only approved extensions)
- **Other responses**: Can emit both payment headers and approved extensions
- **Client requests**: Can emit X-PAYMENT headers for payment verification

## Extensions (optional)

- Approved extension headers (v1): `X-402-Routing`, `X-402-Limits`, `X-402-Acceptable`, `X-402-Metadata`, `X-402-Security`.
- Place as objects in `app.extensions`: each `{ header, payload, ... }` is canonicalized and AAD-bound; optionally uplift via `public.makeEntitiesPublic`.

### X-402-Security Extension

The `X-402-Security` extension enables security negotiation and key management:

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

This extension supports:
- **Key Discovery**: Share JWKS endpoints or inline keys
- **Security Negotiation**: Specify minimum key strength and allowed algorithms
- **Client Key Rotation**: Provide fresh keys for each request

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