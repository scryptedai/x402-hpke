#!/usr/bin/env python3
import sys, json, base64
from x402_hpke import create_hpke

def main():
    data = json.loads(sys.stdin.read())
    ns = data.get("namespace", "myapp")
    hpke = create_hpke(namespace=ns)
    kid = data["kid"]
    recipient_public_jwk = data["recipient_public_jwk"]
    plaintext_b64u = data.get("plaintext_b64u", "")
    plaintext = base64.urlsafe_b64decode((plaintext_b64u + "==").encode("ascii")) if plaintext_b64u else b""
    x402 = data["x402"]
    app = data.get("app")
    env, _ = hpke.seal(kid=kid, recipient_public_jwk=recipient_public_jwk, plaintext=plaintext, x402=x402, app=app)
    print(json.dumps(env))

if __name__ == "__main__":
    main()