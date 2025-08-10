#!/usr/bin/env python3
import sys, json, base64
from x402_hpke import create_hpke
from x402_hpke.secure_transport import x402SecureTransport, TransportType

def main():
    data = json.loads(sys.stdin.read())
    ns = data.get("namespace", "myapp")
    hpke = create_hpke(namespace=ns)
    kid = data["kid"]
    recipient_public_jwk = data["recipient_public_jwk"]
    # Build transport from input
    transport = None
    if "x402" in data:
        x402 = data["x402"] or {}
        header = str(x402.get("header", ""))
        payload = x402.get("payload") or {}
        if header == "X-Payment":
            transport = x402SecureTransport(TransportType.PAYMENT, {"payload": payload})
        elif header == "X-Payment-Response":
            transport = x402SecureTransport(TransportType.PAYMENT_RESPONSE, payload, 200)
        elif header == "":
            transport = x402SecureTransport(TransportType.PAYMENT_REQUIRED, payload)
        else:
            raise ValueError("Unsupported x402 header")
    elif "request" in data:
        request = data["request"] or {}
        transport = x402SecureTransport(TransportType.OTHER_REQUEST, request)
    elif "response" in data:
        response = data["response"] or {}
        http_response_code = int(data.get("httpResponseCode", 200))
        transport = x402SecureTransport(TransportType.OTHER_RESPONSE, response, http_response_code)
    else:
        raise ValueError("One of 'x402', 'request', or 'response' must be provided")

    env, _ = hpke.seal(kid=kid, recipient_public_jwk=recipient_public_jwk, transport=transport)
    print(json.dumps(env))

if __name__ == "__main__":
    main()