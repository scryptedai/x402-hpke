# x402-hpke (Python)

Monorepo: https://github.com/scryptedai/x402-hpke (Python path: `packages/python`, Node path: `packages/node`).

Provider-agnostic HPKE envelope library for x402 (Python). Pinned ciphersuite for interop:
X25519 / HKDF-SHA256 / ChaCha20-Poly1305 (envelope); streaming helpers use XChaCha20-Poly1305.

## Install

Python >= 3.12

```bash
pip install --pre x402-hpke
```

## Quickstart

```python
from x402_hpke import create_hpke, generate_keypair

hpke = create_hpke(namespace="myapp")
pub, priv = generate_keypair()

# Use helpers or transport API; sidecar is private-by-default
from x402_hpke import create_payment
env, headers = create_payment(
    hpke,
    payment_data={"invoiceId": "inv_1"},
    recipient_public_jwk=pub,
    kid="kid1",
    is_public=True,
)
```

## Streaming (Python)

Chunk encryption helpers using XChaCha20-Poly1305:

```python
from x402_hpke import seal_chunk_xchacha, open_chunk_xchacha

key = bytes(32)          # derive via app contract; export API is planned
prefix16 = bytes(16)
seq = 0
ct = seal_chunk_xchacha(key, prefix16, seq, b"chunk")
pt = open_chunk_xchacha(key, prefix16, seq, ct)
```

## JWKS utilities

- `fetch_jwks(url, min_ttl=60, max_ttl=3600)`
- `set_jwks(url, jwks, ttl=300)`
- `select_jwk(kid, jwks=None, url=None)`

## Notes

 - AEAD is pinned to ChaCha20-Poly1305 for v1 (envelope). AES-256-GCM may be offered as an optional profile in future versions for FIPS-oriented environments; suite pinning remains per-version.