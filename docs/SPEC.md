# Technical Design — x402-hpke (pinned for interop)

- Ciphersuite (v1, pinned for maximum interop):
  - KEM: X25519
  - KDF: HKDF-SHA256
  - AEAD (envelope): ChaCha20-Poly1305 (96-bit nonce, libsodium `*_ietf`)
- AAD is canonical; payload is opaque. Public sidecar is a projection of AAD; mismatch rejected.
- JWKS: HTTPS-only fetch with Cache-Control/Expires; selection by `kid`.
- Interop: Node seals ↔ Python opens and vice versa. Cross-language tests included.

Notes:
- We use ChaCha20-Poly1305 for the envelope to align with RFC 9180 (96-bit nonce).
- Streaming helpers use XChaCha20-Poly1305 for chunking (separate key/nonce prefix), see STREAMING.md.