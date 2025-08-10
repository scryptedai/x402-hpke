# AAD (Additional Authenticated Data)

AAD provides integrity protection and binding for all x402 metadata and application data. The AAD is canonicalized to ensure deterministic byte representation across different implementations.

## Canonicalization Rules

- **Deep sort**: Keys are sorted recursively at all levels
- **Compact JSON**: No spaces around separators (`,` and `:`)
- **Array preservation**: Array order is maintained (not sorted)
- **Object sorting**: Objects are sorted lexicographically by key
- **UTF-8 encoding**: All strings encoded as UTF-8 bytes

## AAD Structure

AAD bytes = UTF‑8 of: `<ns>|v1|` + json(headers_array) + `|` + json(body_object)

### headers_array

- Array of normalized header entries: `{ header: string, value: object, ...extras }`
- Header names are canonicalized (core: `X-Payment`, `X-Payment-Response`, or `""`); extensions are case-normalized and must be approved.
- Entries are sorted by `header` (case-insensitive).

### body_object

- Deep-canonicalized `privateBody` (application payload). Top-level keys MUST NOT collide (case-insensitive) with header names.

## Header Usage Rules

### Valid Header Values

- **"X-Payment"**: Client requests with payment (no httpResponseCode).
- **"X-Payment-Response"**: Server responses with payment receipt (requires httpResponseCode: 200; auto-set if omitted).
- **"" (empty)**: Payment Required (402); header value is reassigned into the body.

### HTTP Response Code Validation

- **402 responses**: core headers MUST NOT be emitted in sidecar; approved extensions and selected body keys may be emitted.
- **X-Payment**: MUST NOT set `httpResponseCode`.
- **X-Payment-Response**: Requires `httpResponseCode: 200` (auto-set if omitted).

## Encoding (normative)

- **JSON canonicalization**: UTF-8; keys sorted; compact separators (",").
- **Base64url without padding** for envelope fields `enc`, `aad`, and `ct`.

## Example AAD Construction

### Input Data (canonical)

```typescript
const namespace = "myapp";
const privateHeaders = [
  { header: "X-402-Routing", value: { service: "worker-A", priority: "high" } }
];
const privateBody = { action: "getUserProfile", userId: "user-123" };
```

### Canonicalized AAD

```
myapp|v1|[{"header":"X-402-Routing","value":{"priority":"high","service":"worker-A"}}]|{"action":"getUserProfile","userId":"user-123"}
```

### Breakdown

1. **Namespace**: `myapp`
2. **Version**: `v1`
3. **Headers array**: normalized and sorted.
4. **Body object**: canonicalized application payload.

## Validation

- **Header validation**: Must be core x402 or approved extension; unique by name.
- **Body validation**: Keys must not collide with header names; canonicalizable to JSON.
- **Extension validation**: Headers must be approved and unique
- **Namespace validation**: Cannot be "x402" (reserved)
- **HTTP response code validation**: Enforces header usage rules

## Security Properties

- **Integrity**: AAD is bound to the ciphertext via AEAD
- **Authenticity**: AAD cannot be modified without detection
- **Binding**: All metadata is cryptographically bound to the encrypted payload
- **Deterministic**: Same input always produces same AAD bytes
- **Header validation**: Prevents improper header usage based on HTTP status codes