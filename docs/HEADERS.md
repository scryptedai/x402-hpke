# Headers / Sidecar

- Default: no transport headers are emitted; AAD binds all metadata.
- Optional sidecar via `public` in `seal()`:
  - `revealPayment: true` → emit exactly one of `X-PAYMENT` or `X-PAYMENT-RESPONSE` (compact, canonical JSON of the core `payload`).
  - `extensionsAllowlist: ["X-402-Routing", ...]` → emit approved extension headers with compact, canonical JSON of each extension `payload`.
  - `as`: "headers" (default) or "json" sidecar
- Server must compare sidecar values to those reconstructed from AAD. Mismatch → `400 AAD_MISMATCH`.
- Sidecar keys must be present in AAD; attempts to expose missing keys → `400 PUBLIC_KEY_NOT_IN_AAD`.

Parser requirements (normative)
- Header name matching is case-insensitive.
- Trim optional whitespace (OWS) on values prior to comparison.

Approved extension headers (v1)
- `X-402-Routing` — payload: `{ service: string, region?: string, shard?: string, queue?: string, priority?: "low"|"normal"|"high", deadlineAt?: string, features?: object }`
- `X-402-Limits` — payload: `{ limit?: number, remaining?: number, resetAt?: string, window?: string }`
- `X-402-Acceptable` — payload: `{ labels: string[] }` (e.g., `["sfw","nsfw","risky","jurisdiction-usa-allowed","jurisdiction-brunei-disallowed"]`)
- `X-402-Metadata` — payload: `{ [k: string]: string | number | boolean | object }`

Notes
- Core x402 object is required and consists of `{ header: "X-Payment"|"X-Payment-Response", payload: object, ... }` and is always bound into AAD.
- Extensions are AAD-bound by default under `app.extensions` and can be selectively uplifted to sidecar.
- Redundant legacy projections (e.g., `X-X402-*`) are intentionally not supported.

Examples

JSON sidecar payload alongside envelope:
```
{
  "X-PAYMENT": "{\"invoiceId\":\"inv_123\"}",
  "X-402-Routing": "{\"service\":\"worker-A\",\"priority\":\"high\"}"
}
```

Spec reference: Coinbase x402 (`https://github.com/coinbase/x402`)