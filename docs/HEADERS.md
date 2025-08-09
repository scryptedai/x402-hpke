# Headers / Sidecar

- Default: no `X-X402-*` headers emitted; all x402 fields live in AAD.
- Optional sidecar via `public` in seal():
  - `x402Headers: true` → emit `X-X402-*`
  - `appHeaderAllowlist: ["traceId", ...]` → emit `X-<APPNS>-Trace-Id`, etc.
  - `as`: "headers" (default) or "json" sidecar
- Server must rebuild projection from AAD and compare byte-for-byte. Mismatch → `400 AAD_MISMATCH`.
- Sidecar keys must be present in AAD; attempts to expose missing keys → `400 PUBLIC_KEY_NOT_IN_AAD`.

Example (HTTP headers sidecar):
- `X-X402-Invoice-Id: inv_123`
- `X-X402-Expiry: 1754650000`
- `X-m y a p p-Trace-Id: abc-123` → will be normalized as `X-m y a p p-Trace-Id` for equality; value must match AAD.

Example (JSON sidecar payload alongside envelope):
```json
{
  "X-X402-Invoice-Id": "inv_123",
  "X-X402-Expiry": "1754650000",
  "X-myapp-Trace-Id": "abc-123"
}
```