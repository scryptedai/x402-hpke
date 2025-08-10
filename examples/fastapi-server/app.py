from fastapi import FastAPI, Response, Request
from x402_hpke import create_hpke
import json, time

app = FastAPI()
hpke = create_hpke(namespace="myapp")

# demo keys (in real, load from JWKS/private store)
from x402_hpke.keys import generate_keypair
PUB, PRIV = generate_keypair()

@app.post("/quote")
async def quote(request: Request):
    x402 = {
        "header": "X-Payment",
        "payload": {
            "invoiceId": "inv_demo",
            "chainId": 8453,
            "tokenContract": "0x" + "a"*40,
            "amount": "1000",
            "recipient": "0x" + "b"*40,
            "txHash": "0x" + "c"*64,
            "expiry": int(time.time()) + 600,
            "priceHash": "0x" + "d"*64,
        }
    }
    # App metadata: keep sensitive items in AAD; expose only non-sensitive hints (e.g., trace id)
    trace_id = request.headers.get("X-Trace-Id") or _random_id()
    app_meta = {"traceId": trace_id, "model": "gpt-4o-mini"}
    env, hdrs = hpke.seal(
        kid="kid1",
        recipient_public_jwk=PUB,
        x402=x402,
        public={"makeEntitiesPublic": ["X-PAYMENT"], "as": "headers"},
    )
    headers = {"Cache-Control": "no-store"}
    if hdrs:
        headers.update(hdrs)
    return Response(content=json.dumps(env), status_code=402, media_type="application/x402-envelope+json", headers=headers)

@app.post("/fulfill")
async def fulfill(request: Request):
    env = await request.json()
    try:
        # reconstruct sidecar mapping
        sidecar = {k: v for k, v in request.headers.items() if k.lower() in ("x-x402-invoice-id", "x-x402-expiry", "x-myapp-trace-id")}
        pt, x402_fields, request_fields, response_fields, ext = hpke.open(
            recipient_private_jwk=PRIV,
            envelope=env,
            expected_kid=env.get("kid"),
            public_headers=sidecar,
        )
        return {"ok": True}
    except Exception as e:
        return Response(content=json.dumps({"error": str(e)}), status_code=400) 


def _random_id() -> str:
    import secrets
    return secrets.token_hex(12)