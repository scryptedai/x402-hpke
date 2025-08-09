# Threat model — x402-hpke

This document describes the security goals, non-goals, assumptions, attacker model, mitigations, and operational guidance for x402 HPKE envelopes.

## Goals
- Confidentiality and integrity of application-layer payloads and metadata across untrusted intermediaries (proxies, caches, message queues, sidecars).
- Deterministic interop across Node/Python via pinned ciphersuite and canonical AAD rules.
- Robust key selection/rotation with `kid` and JWKS over HTTPS (+ TTL clamping).
- Safe handling of large/unbounded payloads via XChaCha streaming with explicit limits.

## Non-goals
- Authentication/authorization of clients or servers.
- Transport security or endpoint identity (use TLS to protect transport and origin identity).
- Application-level replay prevention by default (guidance below; implement at app/service layer).
- Traffic analysis protection (metadata sizes/timing may leak; minimize sensitive data in sidecars).
- Post-compromise protection if recipient private key is compromised.

## Assumptions
- Recipient controls and protects X25519 private key material.
- JWKS is fetched via HTTPS with sane cache headers; local TTL clamping is enforced.
- System clocks are reasonably synchronized (for `expiry` semantics).
- Implementations use well-vetted primitives (libsodium) and follow this spec.

## Attacker model
- Network attacker: can observe, inject, replay, and modify messages in transit.
- Malicious intermediaries: proxies/queues can read/alter sidecars or envelope structure.
- Honest-but-buggy integrators: header case/whitespace variances, JSON ordering, or base64 padding mistakes.
- Out of scope: fully compromised endpoints (client or server), key exfiltration, malicious libraries.

## Mitigations and design choices
- Algorithm pinning and binding
  - Suite (v1) is pinned: X25519 / HKDF-SHA256 / ChaCha20-Poly1305. Envelope MAY include `suite`.
  - HKDF `info` binds `KDF`, `AEAD`, `ns`, `enc`, and recipient public key `pkR` to prevent algorithm/context confusion.
- Canonical AAD and sidecar
  - AAD is canonical JSON with deterministic encoding; payload is opaque.
  - Public sidecar is a projection of AAD only; server rebuilds and requires byte-equivalence.
  - Header parsing is case-insensitive; values are trimmed (OWS) before rebuild.
  - AAD equivalence checks MUST be constant-time.
- Low-order/invalid inputs
  - All-zero/key validation on X25519 public/shared secrets; invalid inputs rejected.
- JWKS and `kid`
  - HTTPS-only JWKS fetch, TTL clamping, `kid` selection, and optional `expectedKid` verification at open.
- Streaming
  - XChaCha20-Poly1305 with `prefix16 || le64(seq)` nonce; reject out-of-order/duplicate `seq` at the application protocol.
  - Implementations provide limit-enforcing wrappers; exceeding limits fails closed with `AEAD_LIMIT`.

## Replay guidance (application-level)
AEAD does not prevent replays. To mitigate replays in your application protocol:
- Bind anti-replay data in AAD (so attempts to alter it are detected):
  - A unique per-request nonce/ID.
  - A timestamp or short-lived expiry bound that the server enforces.
  - Optional binding to request context (HTTP method, path, query) if relevant.
- On the receiver, maintain a dedupe cache keyed by `{ns, invoiceId, nonce}` (or your chosen tuple):
  - Keep a sliding window (e.g., 5–15 minutes) aligned with `expiry`.
  - Reject duplicates and stale messages with `AAD_REPLAY` (implementation-specific error code).
- Avoid placing sensitive identifiers in public sidecars if you cannot tolerate leakage through intermediaries.

## Operational guidance
- Logging and redaction: never log envelope `ct`, raw `aad` bytes, or private keys. If logging headers/sidecars for troubleshooting, ensure redaction and retention policies.
- Error taxonomy: use shared errors (e.g., `AEAD_MISMATCH`, `AAD_MISMATCH`, `ECDH_LOW_ORDER`, `NS_FORBIDDEN`, `PUBLIC_KEY_NOT_IN_AAD`, `AEAD_LIMIT`) for consistent diagnostics.
- Clock skew: when enforcing `expiry`, allow reasonable skew and align with the dedupe window.
- Key rotation: prefer staged rotation via JWKS with overlapping validity; verify `kid` on open where possible.
- KATs and interop tests: include KATs in CI to detect drift across implementations.

## Residual risks
- Endpoint compromise (client/server) can leak plaintext and keys; this is out of scope for the envelope.
- Improper replay caching or missing AAD bindings can allow replays.
- Misconfigured JWKS caching may extend exposure after key rotation.

## References
- SPEC: `docs/SPEC.md`
- AAD rules: `docs/AAD.md`
- Sidecars/headers: `docs/HEADERS.md`
- Streaming: `docs/STREAMING.md`