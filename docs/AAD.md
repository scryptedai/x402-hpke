# AAD (Additional Authenticated Data)

AAD provides integrity protection and binding for all x402 metadata and application data. The AAD is canonicalized to ensure deterministic byte representation across different implementations.

## Canonicalization Rules

- **Deep sort**: Keys are sorted recursively at all levels
- **Compact JSON**: No spaces around separators (`,` and `:`)
- **Array preservation**: Array order is maintained (not sorted)
- **Object sorting**: Objects are sorted lexicographically by key
- **UTF-8 encoding**: All strings encoded as UTF-8 bytes

## AAD Structure

AAD bytes = UTF‑8 of: `<ns>|v1|` + json(x402_core) + `|` + json(app?)

### Core (required)

- `x402_core` is a KV object that MUST include:
  - `header`: "X-Payment" or "X-Payment-Response" (case-insensitive input; canonicalized in AAD)
  - `payload`: a non-empty object containing payment details
  - Additional keys are allowed and included in canonicalization

### App (optional)

- `app` MAY include arbitrary KV; for standardized extensions, place an array under `app.extensions` of objects `{ header, payload, ... }`.
- Extension headers must be on the approved list and unique; each `payload` must be a non-empty object.
- Extensions are sorted by `header` (case-insensitive) during canonicalization.

## Encoding (normative)

- **JSON canonicalization**: UTF-8; keys sorted; compact separators (",").
- **Base64url without padding** for envelope fields `enc`, `aad`, and `ct`.

## Example AAD Construction

### Input Data

```typescript
const namespace = "myapp";
const x402 = {
  header: "X-Payment",
  payload: {
    invoiceId: "inv_123",
    amount: "1000",
    chainId: 8453
  }
};
const app = {
  traceId: "req_456",
  extensions: [
    {
      header: "X-402-Routing",
      payload: { service: "worker-A", priority: "high" }
    },
    {
      header: "X-402-Limits", 
      payload: { limit: 1000, remaining: 500 }
    }
  ]
};
```

### Canonicalized AAD

```
myapp|v1|{"amount":"1000","chainId":8453,"header":"X-Payment","invoiceId":"inv_123"}|{"extensions":[{"header":"X-402-Limits","payload":{"limit":1000,"remaining":500}},{"header":"X-402-Routing","payload":{"priority":"high","service":"worker-A"}}],"traceId":"req_456"}
```

### Breakdown

1. **Namespace**: `myapp`
2. **Version**: `v1`
3. **x402 core**: Keys sorted alphabetically (`amount`, `chainId`, `header`, `invoiceId`)
4. **App**: Keys sorted (`extensions`, `traceId`), extensions sorted by header (`X-402-Limits`, `X-402-Routing`)

## Validation

- **Header validation**: Must be "X-Payment" or "X-Payment-Response" (case-insensitive)
- **Payload validation**: Must be a non-empty object
- **Extension validation**: Headers must be approved and unique
- **Namespace validation**: Cannot be "x402" (reserved)

## Security Properties

- **Integrity**: AAD is bound to the ciphertext via AEAD
- **Authenticity**: AAD cannot be modified without detection
- **Binding**: All metadata is cryptographically bound to the encrypted payload
- **Deterministic**: Same input always produces same AAD bytes