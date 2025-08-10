#!/usr/bin/env python3
import sys, json, base64
from x402_hpke import create_hpke

def main():
    data = json.loads(sys.stdin.read())
    ns = data.get("namespace", "myapp")
    hpke = create_hpke(namespace=ns)
    kid = data["kid"]
    recipient_public_jwk = data["recipient_public_jwk"]
    # Handle different payload types
    if "x402" in data:
        x402 = data["x402"]
        env, _ = hpke.seal(kid=kid, recipient_public_jwk=recipient_public_jwk, x402=x402)
    elif "request" in data:
        request = data["request"]
        env, _ = hpke.seal(kid=kid, recipient_public_jwk=recipient_public_jwk, request=request)
    elif "response" in data:
        response = data["response"]
        http_response_code = data.get("httpResponseCode", 200)
        env, _ = hpke.seal(kid=kid, recipient_public_jwk=recipient_public_jwk, response=response, http_response_code=http_response_code)
    else:
        raise ValueError("One of 'x402', 'request', or 'response' must be provided")
    print(json.dumps(env))

if __name__ == "__main__":
    main()