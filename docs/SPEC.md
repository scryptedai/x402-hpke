# Technical Design — x402-hpke (Hybrid Public Key Encryption, HPKE; pinned for interop)

- Ciphersuite (v1, pinned for maximum interop):
  - KEM (Key Encapsulation Mechanism): X25519
  - KDF (Key Derivation Function): HKDF-SHA256
  - AEAD (Authenticated Encryption with Associated Data, envelope): ChaCha20-Poly1305 (96-bit nonce, libsodium `*_ietf`)
  - Suite ID: `X25519-HKDF-SHA256-CHACHA20POLY1305`
  - Envelope MAY include `suite` field; APIs expose `hpke.suite` and `hpke.version`.
- AAD (Additional Authenticated Data) is canonical; payload is opaque. Public sidecar is a projection of AAD; mismatch rejected.
- JWKS (JSON Web Key Set): HTTPS-only fetch with Cache-Control/Expires; selection by `kid`.
- Interop: Node seals ↔ Python opens and vice versa. Cross-language tests included.

Media type
- Provisional media type for content negotiation: `application/x402-envelope+json`.

Notes:
- We use ChaCha20-Poly1305 for the envelope to align with RFC 9180 (96-bit nonce).
- Streaming helpers use XChaCha20-Poly1305 for chunking (separate key/nonce prefix), see STREAMING.md.

HKDF info binding (normative)
- Seal: `"x402-hpke:v1|KDF=<KDF>|AEAD=<AEAD>|ns=<NS>|enc=<ENC>|pkR=<PKR>"`
- Open: `"x402-hpke:v1|KDF=<KDF>|AEAD=<AEAD>|ns=<NS>|enc=<ENC>|pkR=<PKR>"`
  - `<ENC>` and `<PKR>` are base64url (no padding)

Equality checks (normative)
- Implementations MUST use constant-time comparisons when checking AAD equivalence or tags (e.g., `timingSafeEqual` in Node, `hmac.compare_digest` in Python).