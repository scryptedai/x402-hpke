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

## Expected interactions

| Intent                        | Helper                  | x402 | Client | Server |
|--------------------------------|-------------------------|------|--------|--------|
| Send a Service Request         | createRequest           | no   | yes    | no     |
| Send a 402 Payment Required    | createPaymentRequired   | yes  | no     | yes    |
| Send a Payment                 | createPayment           | yes  | yes    | no     |
| Send a Payment Response        | createPaymentResponse   | yes  | no     | yes    |
| Send some other Response       | createResponse          | no   | no     | yes    |

## Canonical data model

There are two kinds of inputs to sealing:

- `privateHeaders` (optional): array of header entries `{ header: string, value: object, ...extras }`
  - Core headers: `"X-Payment"`, `"X-Payment-Response"`, and the empty string `""`.
  - Approved extension headers: e.g., `X-402-Routing`, `X-402-Limits`, `X-402-Acceptable`, `X-402-Metadata`, `X-402-Security`.
  - Headers are unique by case-insensitive name.
- `privateBody` (optional): JSON object carrying application payload (generic request/response or confidential body).

Collision rule: top-level keys in `privateBody` MUST NOT equal any header name (case-insensitive).

### Core x402 header rules

- X-Payment: MUST NOT set `httpResponseCode`. Its value MUST be a JSON object that includes at least a `payload` field; other fields are allowed.
- X-Payment-Response: MUST have `httpResponseCode: 200`. If not set, it is auto-set to 200.
- Payment Required (402): Uses the empty core header `""`. The header value is reassigned into `privateBody`, and `httpResponseCode` MUST be 402 (auto-set if not provided).

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

The canonical sealing inputs are `privateHeaders` and `privateBody`. For backwards-compatibility, helpers and legacy fields (`request`, `response`, `x402`) are supported and internally mapped to the canonical model.

#### Generic Request/Response

```typescript
// Seal a request (legacy convenience)
const { envelope, publicJsonBody } = await hpke.seal({
  request: { action: "getData", params: { id: 123 } },
  public: { makeEntitiesPublic: ["request"], as: "json" }
});
// Canonical equivalent
const { envelope, publicBody } = await hpke.seal({
  privateBody: { action: "getData", params: { id: 123 } },
  public: { makeEntitiesPublic: ["action", "params"], as: "json" }
});
```

If `makeEntitiesPublic` includes `"request"` or `"response"` using the legacy path, Node returns `publicJsonBody`. Canonically, use `publicBody` with selected body keys.

#### Payment Protocol (x402)

For convenience, `x402` continues to be supported and maps to `privateHeaders`.

```typescript
// Seal X-Payment (maps to privateHeaders)
const { envelope, publicHeaders } = await hpke.seal({
  x402: { header: "X-Payment", payload: {/*...*/} },
  public: { makeEntitiesPublic: ["X-PAYMENT"] }
});
```

### Sidecar Generation

The sidecar is a projection from the canonical inputs:

- `publicHeaders`: for any header names selected via `makeEntitiesPublic`, values are emitted as compact canonical JSON strings. Core headers use upper-case keys `X-PAYMENT` and `X-PAYMENT-RESPONSE`.
- `publicBody`: for any top-level body keys selected via `makeEntitiesPublic`, those fields are emitted in a JSON object (only when `as: "json"`).

Controls:
- `makeEntitiesPublic: "all" | "*" | string[]` — choose header names and/or body keys.
- `makeEntitiesPrivate: string[]` — subtract from the public set.
- `as: "headers" | "json"` — when `json`, `publicHeaders` is returned as a JSON object and `publicBody` is available; when `headers`, only headers are emitted.

### HTTP Response Code Behavior

The `httpResponseCode` parameter controls sidecar behavior and enforces header validation:

- 402 responses: Never emit core x402 headers in sidecar; approved extensions may be emitted; body projections may be emitted.
- Other responses: May emit core x402 headers and approved extensions as requested.
- Client requests: May emit `X-PAYMENT` for verification.

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
  - `<ENC>` and `<PKR>` are base64url (no padding); `<NS>` MUST match the envelope namespace.

## Equality checks (normative)

- Implementations MUST use constant-time comparisons when checking sidecar equivalence or tags. Compare header values and body projections to AAD-bound values using constant-time semantics.