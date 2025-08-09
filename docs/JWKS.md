# JWKS

- Keys are OKP X25519 JWKs with `kty=OKP`, `crv=X25519`, `x` (and `d` for private).
- `kid` is required and used for recipient selection.
- JWKS cache should honor Cache-Control (future enhancement).