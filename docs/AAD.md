# AAD (Additional Authenticated Data)

AAD provides integrity protection and binding for all x402 metadata and application data. The AAD is canonicalized to ensure deterministic byte representation across different implementations.

## Canonicalization Rules

- **Deep sort**: Keys are sorted recursively at all levels
- **Compact JSON**: No spaces around separators (`,` and `:`)
- **Array preservation**: Array order is maintained (not sorted)
- **Object sorting**: Objects are sorted lexicographically by key
- **UTF-8 encoding**: All strings encoded as UTF-8 bytes

## AAD Structure

AAD bytes = UTF‑8 of: `<ns>|v1|` + json(primary_payload) + `|` + json(extensions?)

### Primary Payload

The `primary_payload` is one of the following:

- **`request`**: A generic request object.
- **`response`**: A generic response object.
- **`x402`**: A specialized `x402` object for payment protocol messages.

### Extensions (optional)

- `extensions` is an array of `{ header, payload }` objects for approved extensions.
- Extensions are sorted by `header` (case-insensitive) during canonicalization.

## Header Usage Rules

### Valid Header Values

- **"X-Payment"**: Client requests with payment (no httpResponseCode)
- **"X-Payment-Response"**: Server responses with payment receipt (requires httpResponseCode: 200)
- **"" (empty)**: Confidential requests/responses (402 or other status codes)

### HTTP Response Code Validation

- **402 responses**: Either use a generic `response` with `httpResponseCode: 402` (recommended), or an `x402` object with empty header `""`.
- **X-Payment**: No `httpResponseCode` should be set (client requests)
- **X-Payment-Response**: Requires `httpResponseCode: 200`

## Encoding (normative)

- **JSON canonicalization**: UTF-8; keys sorted; compact separators (",").
- **Base64url without padding** for envelope fields `enc`, `aad`, and `ct`.

## Example AAD Construction

### Input Data

```typescript
const namespace = "myapp";
const request = {
  action: "getUserProfile",
  userId: "user-123"
};
const extensions = [
  {
    header: "X-402-Routing",
    payload: { service: "worker-A", priority: "high" }
  }
];
```

### Canonicalized AAD

```
myapp|v1|{"action":"getUserProfile","userId":"user-123"}|[{"header":"X-402-Routing","payload":{"priority":"high","service":"worker-A"}}]
```

### Breakdown

1. **Namespace**: `myapp`
2. **Version**: `v1`
3. **Primary Payload**: The `request` object, canonicalized.
4. **Extensions**: The `extensions` array, sorted and canonicalized.

## Validation

- **Header validation**: Must be "X-Payment", "X-Payment-Response", or "" (empty)
- **Payload validation**: Must be a non-empty object
- **Extension validation**: Headers must be approved and unique
- **Namespace validation**: Cannot be "x402" (reserved)
- **HTTP response code validation**: Enforces header usage rules

## Security Properties

- **Integrity**: AAD is bound to the ciphertext via AEAD
- **Authenticity**: AAD cannot be modified without detection
- **Binding**: All metadata is cryptographically bound to the encrypted payload
- **Deterministic**: Same input always produces same AAD bytes
- **Header validation**: Prevents improper header usage based on HTTP status codes