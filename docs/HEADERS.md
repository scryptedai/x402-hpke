# Headers / Sidecar

- Default: no `X-X402-*` headers emitted; all x402 fields live in AAD.
- Optional sidecar via `public` in `seal()`:
  - `x402Headers: true` → emit `X-X402-*`
  - `appHeaderAllowlist: ["traceId", ...]` → emit `X-<ns>-Trace-Id`, etc.
  - `as`: "headers" (default) or "json" sidecar
- Server must rebuild projection from AAD and compare byte-for-byte. Mismatch → `400 AAD_MISMATCH`.
- Sidecar keys must be present in AAD; attempts to expose missing keys → `400 PUBLIC_KEY_NOT_IN_AAD`.

## Header names

- `X-X402-Invoice-Id`
- `X-X402-Chain-Id`
- `X-X402-Token-Contract`
- `X-X402-Amount`
- `X-X402-Recipient`
- `X-X402-Tx-Hash`
- `X-X402-Expiry`
- `X-X402-Price-Hash`

## Application headers

- Allowlist via `appHeaderAllowlist` in `seal()`; each allowed key `k` yields `X-<ns>-<k>`.
- All app keys must also be present in AAD (else `PUBLIC_KEY_NOT_IN_AAD`).

## Examples

HTTP headers sidecar:
- `X-X402-Invoice-Id: inv_123`
- `X-X402-Expiry: 1754650000`
- `X-myapp-Trace-Id: abc-123`

JSON sidecar payload alongside envelope:
```json
{
  "X-X402-Invoice-Id": "inv_123",
  "X-X402-Expiry": "1754650000",
  "X-myapp-Trace-Id": "abc-123"
}
```