# AAD (Additional Authenticated Data)

- Canonicalization: deep sort of keys with compact JSON separators (no spaces). Arrays preserve order; objects sorted lexicographically by key.
- AAD bytes = UTF‑8 of: `<ns>|v1|` + json(x402_core) + `|` + json(app?).

Core (required)
- `x402_core` is a KV object that MUST include:
  - `header`: "X-Payment" or "X-Payment-Response" (case-insensitive input; canonicalized in AAD)
  - `payload`: a non-empty object
  - Additional keys are allowed and included in canonicalization

App (optional)
- `app` MAY include arbitrary KV; for standardized extensions, place an array under `app.extensions` of objects `{ header, payload, ... }`.
- Extension headers must be on the approved list and unique; each `payload` must be a non-empty object.
- Extensions are sorted by `header` (case-insensitive) during canonicalization.

Encoding (normative)
- JSON canonicalization: UTF-8; keys sorted; compact separators (",").
- Base64url without padding for envelope fields `enc`, `aad`, and `ct`.