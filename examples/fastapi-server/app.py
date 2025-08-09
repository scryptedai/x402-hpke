from fastapi import FastAPI, Response, Request
from x402_hpke import create_hpke
import json, time

app = FastAPI()
hpke = create_hpke(namespace="myapp")

# demo keys (in real, load from JWKS/private store)
from x402_hpke.keys import generate_keypair
PUB, PRIV = generate_keypair()

@app.post("/quote")
async def quote():
    x402 = {
        "invoiceId": "inv_demo",
        "chainId": 8453,
        "tokenContract": "0x" + "a"*40,
        "amount": "1000",
        "recipient": "0x" + "b"*40,
        "txHash": "0x" + "c"*64,
        "expiry": int(time.time()) + 600,
        "priceHash": "0x" + "d"*64,
    }
    payload = json.dumps({"type": "quote"}).encode()
    env, _ = hpke.seal(kid="kid1", recipient_public_jwk=PUB, plaintext=payload, x402=x402)
    return Response(content=json.dumps(env), status_code=402, media_type="application/myapp+hpke", headers={"Cache-Control": "no-store"})

@app.post("/fulfill")
async def fulfill(request: Request):
    env = await request.json()
    try:
        pt, x402_fields, app_fields = hpke.open(recipient_private_jwk=PRIV, envelope=env, expected_kid=env.get("kid"))
        return {"ok": True}
    except Exception as e:
        return Response(content=json.dumps({"error": str(e)}), status_code=400) 