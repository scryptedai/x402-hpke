# Headers / Sidecar

- **Default**: No transport headers are emitted; AAD binds all metadata.
- **Optional sidecar** via `public` in `seal()`:
  - `makeEntitiesPublic: "all" | "*" | ["X-PAYMENT", "X-402-Routing", ...]` → emit entities (all or selected)
  - `makeEntitiesPrivate: ["traceId", ...]` → subtract entities from the public set
  - `as: "headers"` (default) or `"json"` → sidecar format
- Server must compare sidecar values to those reconstructed from AAD. Mismatch → `400 AAD_MISMATCH`.
- Sidecar keys must be present in AAD; attempts to expose missing keys → `400 PUBLIC_KEY_NOT_IN_AAD`.

## HTTP Response Code Behavior

The `httpResponseCode` parameter in `seal()` controls sidecar behavior:

- **402 responses**: Never emit X-PAYMENT headers in sidecar (only approved extensions)
- **Other responses**: Can emit both payment headers and approved extensions  
- **Client requests**: Can emit X-PAYMENT headers for payment verification

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

## Parser requirements (normative)

- Header name matching is case-insensitive.
- Trim optional whitespace (OWS) on values prior to comparison.

## Approved extension headers (v1)

- `X-402-Routing` — payload: `{ service: string, region?: string, shard?: string, queue?: string, priority?: "low"|"normal"|"high", deadlineAt?: string, features?: object }`
- `X-402-Limits` — payload: `{ limit?: number, remaining?: number, resetAt?: string, window?: string }`
- `X-402-Acceptable` — payload: `{ labels: string[] }` (e.g., `["sfw","nsfw","risky","jurisdiction-usa-allowed","jurisdiction-brunei-disallowed"]`)
- `X-402-Metadata` — payload: `{ [k: string]: string | number | boolean | object }`

## Notes

- Core x402 object is required and consists of `{ header: "X-Payment"|"X-Payment-Response", payload: object, ... }` and is always bound into AAD.
- Extensions are AAD-bound by default under `app.extensions` and can be selectively uplifted to sidecar via `makeEntitiesPublic`.
- The `makeEntitiesPrivate` mechanism allows fine-grained control over which entities are exposed.

## Examples

### Headers sidecar
```http
X-PAYMENT: {"invoiceId":"inv_123"}
X-402-Routing: {"service":"worker-A","priority":"high"}
X-myapp-traceId: "req_456"
```

### JSON sidecar payload alongside envelope
```json
{
  "X-PAYMENT": "{\"invoiceId\":\"inv_123\"}",
  "X-402-Routing": "{\"service\":\"worker-A\",\"priority\":\"high\"}",
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
```typescript
// 402 responses only emit extensions, never payment headers
const { envelope, publicHeaders } = await hpke.seal({
  // ... other params
  httpResponseCode: 402,
  public: {
    makeEntitiesPublic: ["X-402-Routing", "X-402-Limits"]
  }
});
// publicHeaders will only contain extension headers, no X-PAYMENT
```

Spec reference: Coinbase x402 (`https://github.com/coinbase/x402`)