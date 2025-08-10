# Python Examples (x402-hpke)

## Server (FastAPI)
File: `examples/fastapi-server/app.py`

- 402 quote response (no X-X402-* headers): returns HPKE envelope.
- Fulfill: accepts envelope (and optional sidecar headers), validates AAD equivalence, decrypts, then proceed to facilitator.

Run:
```bash
cd packages/python
poetry install
poetry run uvicorn examples.fastapi-server.app:app --reload
```

## Client (Python)
File: `examples/client-python/client.py`

- Seals payload + AAD.
- Public sidecar: use helper `is_public=True` or direct `make_entities_public` selection; private by default.

Run:
```bash
cd packages/python
poetry run python examples/client-python/client.py
```

## Library API Highlights

```python
from x402_hpke import (
    create_hpke,
    create_payment,
    create_payment_required,
    create_payment_response,
)
from x402_hpke.keys import generate_keypair

hpke = create_hpke(namespace="myapp")
PUB, PRIV = generate_keypair()

env, headers = create_payment(
    hpke,
    payment_data={  # required fields
        "invoiceId": "inv_1", "chainId": 8453, "tokenContract": "0x"+"a"*40,
        "amount": "1000", "recipient": "0x"+"b"*40, "txHash": "0x"+"c"*64,
        "expiry": 1754650000, "priceHash": "0x"+"d"*64,
    },
    recipient_public_jwk=PUB,
    kid="kid-2025",
    is_public=True,
)

pt, body, headers2 = hpke.open(
    recipient_private_jwk=PRIV,
    envelope=env,
    expected_kid="kid-2025",
    public_headers=headers,
)
```

## Interop
- A Node interop test seals in Python and opens in Node. See Node tests.