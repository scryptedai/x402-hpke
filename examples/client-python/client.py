import requests, json, time
from x402_hpke import create_hpke
from x402_hpke.keys import generate_keypair

hpke = create_hpke(namespace="myapp")
PUB, PRIV = generate_keypair()

x402 = {
    "header": "X-Payment",
    "payload": {
        "invoiceId": "inv_client_py",
        "chainId": 8453,
        "tokenContract": "0x" + "a"*40,
        "amount": "1000",
        "recipient": "0x" + "b"*40,
        "txHash": "0x" + "c"*64,
        "expiry": int(time.time())+600,
        "priceHash": "0x" + "d"*64,
    }
}

env, headers = hpke.seal(kid="kid1", recipient_public_jwk=PUB, x402=x402, public={"makeEntitiesPublic": ["X-PAYMENT"], "as": "headers"})

requests.post("http://localhost:3000/fulfill", json=env, headers=headers or {})