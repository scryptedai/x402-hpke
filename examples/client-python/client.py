import requests, json, time
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../packages/python")))
from x402_hpke import create_hpke, create_payment
from x402_hpke.keys import generate_keypair

hpke = create_hpke(namespace="myapp")
PUB, PRIV = generate_keypair()

env, headers = create_payment(
    hpke,
    payment_data={"invoiceId": "inv_client_py"},
    recipient_public_jwk=PUB,
    kid="kid1",
    is_public=True,
)

requests.post("http://localhost:3000/fulfill", json=env, headers=headers or {})