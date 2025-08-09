# x402-hpke (Python)

Monorepo: https://github.com/scryptedai/x402-hpke (Python path: `packages/python`, Node path: `packages/node`).

Provider-agnostic HPKE envelope library for x402 (Python). Pinned ciphersuite for interop:
X25519 / HKDF-SHA256 / ChaCha20-Poly1305 (envelope); streaming helpers use XChaCha20-Poly1305.

## Install

Python >= 3.12

```bash
pip install x402-hpke
```

## Quickstart

```python
from x402_hpke import create_hpke, generate_keypair, build_x402_headers

hpke = create_hpke(namespace="myapp")
pub, priv = generate_keypair()

x402 = {
    "invoiceId": "inv_1",
    "chainId": 8453,
    "tokenContract": "0x" + "a"*40,
    "amount": "1000",
    "recipient": "0x" + "b"*40,
    "txHash": "0x" + "c"*64,
    "expiry": 9999999999,
    "priceHash": "0x" + "d"*64,
}

envelope, headers = hpke.seal(
    kid="kid1",
    recipient_public_jwk=pub,
    plaintext=b"hello",
    x402=x402,
    public={"x402Headers": True},
)

pt, xnorm, app = hpke.open(
    recipient_private_jwk=priv,
    envelope=envelope,
    expected_kid="kid1",
    public_headers=headers,
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