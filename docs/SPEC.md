# Technical Design Document — x402-hpke (updated)

- Envelope AEAD default: ChaCha20-Poly1305 (RFC 9180); streaming uses exported key (future XChaCha recommended).
- AAD is canonical; payload is opaque. Public sidecar is a projection of AAD; mismatch rejected.
- JWKS: HTTPS-only fetch with cache-control; selection by kid.
- Interop: Node seals → Python opens and vice versa planned; Node→Python test included.