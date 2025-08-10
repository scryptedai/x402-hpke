# Headers / Sidecar

- **Default**: No transport headers are emitted; AAD binds all metadata.
- **Optional sidecar** via `public` in `seal()`:
  - `makeEntitiesPublic: "all" | "*" | ["X-PAYMENT", "X-402-Routing", "action", ...]` → emit selected header names and/or body keys
  - `makeEntitiesPrivate: ["traceId", ...]` → subtract entities from the public set
  - `as: "headers"` (default) or `"json"` → when `json`, both `publicHeaders` (as a JSON object) and `publicBody` (selected body keys) may be returned
- Server must compare sidecar values to those reconstructed from AAD. Mismatch → `400 AAD_MISMATCH`.
- Sidecar keys must be present in AAD; attempts to expose missing keys → `400 PUBLIC_KEY_NOT_IN_AAD`.

## HTTP Response Code Behavior

The `httpResponseCode` parameter in `seal()` controls sidecar behavior and enforces header validation:

- **402 responses**: Never emit core x402 headers (X-PAYMENT/X-PAYMENT-RESPONSE) in sidecar; approved extensions and selected body keys may be emitted.
- **Other responses**: Can emit both core x402 headers and approved extensions as requested.
- **Client requests**: Can emit X-PAYMENT headers for payment verification

### Header Usage Rules

- **"X-Payment"**: Client requests with payment (no httpResponseCode)
- **"X-Payment-Response"**: Server responses with payment receipt (requires httpResponseCode: 200)
- **"" (empty)**: Confidential requests/responses (402 or other status codes)

### HTTP Response Code Validation

- **402 responses**: `x402.header` MUST be `""` (empty) - never "X-Payment" or "X-Payment-Response"
- **X-Payment**: No `httpResponseCode` should be set (client requests)
- **X-Payment-Response**: Requires `httpResponseCode: 200`

This ensures that 402 Payment Required responses don't leak payment information in headers while still allowing extension metadata for routing and limits.

## Entity Management

### Constructor Defaults

Set defaults at HPKE creation time for consistent behavior:

```typescript
const hpke = createHpke({
  namespace: "myapp",
  x402: { header: "X-Payment", payload: { /* default payment */ } },
  app: { traceId: "default", model: "gpt-4" },
  publicEntities: "all" // or specific list
});
```

### Per-Call Overrides

Override defaults per operation:

```typescript
const { envelope, publicHeaders } = await hpke.seal({
  // ... other params
  x402: { /* override constructor default */ },
  app: { /* merge with constructor default */ },
  public: {
    makeEntitiesPublic: ["X-PAYMENT", "X-402-Routing"], // specific entities
    makeEntitiesPrivate: ["traceId"], // hide specific entities
    as: "json" // JSON sidecar instead of headers
  }
});
```

## Sidecar Generation

Sidecars are generated based on the `public` parameter in the `seal` method.

### Generic Request/Response

If using the legacy `request`/`response` fields, `makeEntitiesPublic: ["request"|"response"]` returns the object as `publicJsonBody` (Node) or is suppressed by helpers to keep return signatures consistent. Canonically, use `publicBody` with named body keys via `makeEntitiesPublic` and `as: "json"`.

```typescript
// Seal a request and expose it as a JSON body
const { envelope, publicJsonBody } = await hpke.seal({
  request: { action: "getData", params: { id: 123 } },
  // ... other seal params
  public: { makeEntitiesPublic: ["request"] }
});
```

### Payment Protocol (`x402`) and Extensions

For `x402` payloads and extensions, the sidecar is generated as headers (or a JSON object of headers). Core headers use upper-case keys: `X-PAYMENT`, `X-PAYMENT-RESPONSE`.

```typescript
// Seal an X-Payment header and an extension header
const { envelope, publicHeaders } = await hpke.seal({
  x402: {
    header: "X-Payment",
    payload: { /* ... */ }
  },
  extensions: [{
    header: "X-402-Routing",
    payload: { service: "worker-A" }
  }],
  // ... other seal params
  public: { makeEntitiesPublic: ["X-Payment", "X-402-Routing"] }
});
```

## Parser requirements (normative)

- Header name matching is case-insensitive.
- Trim optional whitespace (OWS) on values prior to comparison.

## Approved extension headers (v1)

- `X-402-Routing` — payload: `{ service: string, region?: string, shard?: string, queue?: string, priority?: "low"|"normal"|"high", deadlineAt?: string, features?: object }`
- `X-402-Limits` — payload: `{ limit?: number, remaining?: number, resetAt?: string, window?: string }`
- `X-402-Acceptable` — payload: `{ labels: string[] }` (e.g., `["sfw","nsfw","risky","jurisdiction-usa-allowed","jurisdiction-brunei-disallowed"]`)
- `X-402-Metadata` — payload: `{ [k: string]: string | number | boolean | object }`
- `X-402-Security` — payload: `{ jwksUrl?: string, jwks?: object, minKeyStrength?: number, allowedSuites?: string[] }`

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

## Notes

- Core x402 object is required and consists of `{ header: "X-Payment"|"X-Payment-Response"|"", payload: object, ... }` and is always bound into AAD.
- Extensions are AAD-bound by default under `app.extensions` and can be selectively uplifted to sidecar via `makeEntitiesPublic`.
- The `makeEntitiesPrivate` mechanism allows fine-grained control over which entities are exposed.

## Examples

### Headers sidecar
```http
X-PAYMENT: {"invoiceId":"inv_123"}
X-402-Routing: {"service":"worker-A","priority":"high"}
X-402-Security: {"jwksUrl":"https://example.com/.well-known/jwks.json"}
X-myapp-traceId: "req_456"
```

### JSON sidecar payload alongside envelope
```json
{
  "X-PAYMENT": "{\"invoiceId\":\"inv_123\"}",
  "X-402-Routing": "{\"service\":\"worker-A\",\"priority\":\"high\"}",
  "X-402-Security": "{\"jwksUrl\":\"https://example.com/.well-known/jwks.json\"}",
  "X-myapp-traceId": "req_456"
}
```

### Selective entity exposure
```typescript
// Only expose payment and routing, hide traceId
public: {
  makeEntitiesPublic: ["X-PAYMENT", "X-402-Routing"],
  makeEntitiesPrivate: ["traceId"]
}
```

### 402 response behavior

For 402 Payment Required, the library supports two equivalent patterns:

1) Recommended (helpers use this): generic `response` payload with `httpResponseCode: 402`.

```typescript
// Using a generic response for 402
const { envelope, publicHeaders } = await hpke.seal({
  response: { status: "payment-required", cost: "1000", currency: "USD" },
  httpResponseCode: 402,
  // Sidecar for 402 never includes X-PAYMENT headers; only approved extensions may be emitted
  public: { makeEntitiesPublic: ["X-402-Routing", "X-402-Limits"], as: "headers" }
});
// publicHeaders will only contain approved extension headers (if requested)
```

2) Also valid: core x402 empty header `""`; its value is reassigned to the body, and no core x402 headers are emitted in sidecar.

```typescript
const { envelope, publicHeaders } = await hpke.seal({
  x402: { header: "", payload: { /* confidential */ } },
  httpResponseCode: 402,
  public: { makeEntitiesPublic: ["X-402-Routing"], as: "headers" }
});
```

### X-Payment-Response with 200 status
```typescript
// X-Payment-Response requires httpResponseCode: 200
const { envelope, publicHeaders } = await hpke.seal({
  // ... other params
  httpResponseCode: 200,
  x402: { header: "X-Payment-Response", payload: { /* payment receipt */ } },
  public: {
    makeEntitiesPublic: ["X-PAYMENT-RESPONSE", "X-402-Security"]
  }
});
```

Spec reference: Coinbase x402 (`https://github.com/coinbase/x402`)