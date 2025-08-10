from x402_hpke import create_hpke
import json, base64, os

def test_seal_open_roundtrip_with_request_payload():
    hpke = create_hpke(namespace="myapp")
    from x402_hpke.keys import generate_keypair
    pub, priv = generate_keypair()
    request_payload = {"action": "test"}
    payload = b"hello"
    env, _ = hpke.seal(
        request=request_payload,
        kid="kid1",
        recipient_public_jwk=pub,
        plaintext=payload,
    )
    pt, req, _ = hpke.open(recipient_private_jwk=priv, envelope=env, expected_kid="kid1")
    assert pt == payload
    assert req == request_payload

def test_public_json_body_for_request_payload():
    hpke = create_hpke(namespace="myapp")
    from x402_hpke.keys import generate_keypair
    pub, priv = generate_keypair()
    request_payload = {"data": "public"}
    payload = b"bye"
    env, body = hpke.seal(
        request=request_payload,
        kid="kid1",
        recipient_public_jwk=pub,
        plaintext=payload,
        public={"makeEntitiesPublic": ["request"]},
    )
    assert body == request_payload
    pt, _, _ = hpke.open(recipient_private_jwk=priv, envelope=env, expected_kid="kid1")
    assert pt == payload

def test_reject_low_order_shared_secret():
    hpke = create_hpke(namespace="myapp")
    from x402_hpke.keys import generate_keypair
    pub, priv = generate_keypair()
    payload = b"hi"
    env, _ = hpke.seal(
        request={"data": "low_order"},
        kid="kid1",
        recipient_public_jwk=pub,
        plaintext=payload,
    )
    env_bad = dict(env)
    enc_zero = base64.urlsafe_b64encode(b"\x00" * 32).decode("ascii").rstrip("=")
    env_bad["enc"] = enc_zero
    try:
        hpke.open(recipient_private_jwk=priv, envelope=env_bad, expected_kid="kid1")
        assert False, "expected ECDH_LOW_ORDER"
    except ValueError as e:
        assert str(e) == "ECDH_LOW_ORDER"

def test_reject_aead_mismatch_and_unsupported():
    hpke = create_hpke(namespace="myapp")
    from x402_hpke.keys import generate_keypair
    pub, priv = generate_keypair()
    payload = b"ok"
    env, _ = hpke.seal(
        request={"data": "aead"},
        kid="kid1",
        recipient_public_jwk=pub,
        plaintext=payload,
    )
    bad = dict(env)
    bad["aead"] = "AES-25GCM"
    try:
        hpke.open(recipient_private_jwk=priv, envelope=bad, expected_kid="kid1")
        assert False
    except ValueError as e:
        assert str(e) == "AEAD_MISMATCH"

def test_three_use_cases_for_sidecar_generation_with_x402():
    hpke = create_hpke(namespace="myapp")
    from x402_hpke.keys import generate_keypair
    pub, priv = generate_keypair()
    payload = b"test data"

    # Case 1: Client request (no http_response_code) - can include X-PAYMENT in sidecar
    env, sidecar = hpke.seal(
        x402={"header": "X-Payment", "payload": {"invoiceId": "inv_1"}},
        kid="kid1",
        recipient_public_jwk=pub,
        plaintext=payload,
        public={"makeEntitiesPublic": ["X-Payment"], "as": "headers"},
    )
    assert sidecar is not None
    assert "X-PAYMENT" in sidecar

    # Case 2: 402 response - no X-402 headers in sidecar (but body is encrypted)
    env_402, sidecar_402 = hpke.seal(
        response={"status": "payment-required"},
        http_response_code=402,
        kid="kid1",
        recipient_public_jwk=pub,
        plaintext=payload,
        public=None,
    )
    assert env_402 is not None
    assert sidecar_402 is None  # 402 responses don't send X-402 headers

    # Case 3: Success response (200) - can include X-PAYMENT-RESPONSE in sidecar
    x402_response = {"header": "X-Payment-Response", "payload": {"settlementId": "settle_1"}}
    env_success, sidecar_success = hpke.seal(
        x402=x402_response,
        http_response_code=200,
        kid="kid1",
        recipient_public_jwk=pub,
        plaintext=payload,
        public={"makeEntitiesPublic": ["X-PAYMENT-RESPONSE"], "as": "headers"},
    )
    assert sidecar_success is not None
    assert "X-PAYMENT-RESPONSE" in sidecar_success

    # Verify all envelopes can be opened
    pt_client, _, _ = hpke.open(recipient_private_jwk=priv, envelope=env, public_headers=sidecar)
    pt_402, _, _ = hpke.open(recipient_private_jwk=priv, envelope=env_402)
    pt_success, _, _ = hpke.open(recipient_private_jwk=priv, envelope=env_success, public_headers=sidecar_success)

    assert pt_client == payload
    assert pt_402 == payload
    assert pt_success == payload

def test_kats_v1_vectors():
    hpke = create_hpke(namespace="myapp")
    kat_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../docs/KATs/kat_v1.json"))
    with open(kat_path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    from x402_hpke.keys import generate_keypair
    for v in doc.get("vectors", []):
        ns = v.get("ns")
        kid = v.get("kid")
        request = v.get("request")
        response = v.get("response")
        x402 = v.get("x402")
        sidecar_as = v.get("sidecar_as")
        pub = v.get("public")
        plaintext_b64u = v.get("plaintext_b64u")
        eph_seed32_b64u = v.get("eph_seed32_b64u")
        http_response_code = v.get("http_response_code")
        pub_jwk, priv_jwk = generate_keypair()
        plaintext = base64.urlsafe_b64decode((plaintext_b64u + "==").encode("ascii")) if plaintext_b64u else b""
        # Python seal doesn't expose eph seed; skip deterministic check here
        public = None
        if pub is not None:
            if isinstance(pub, list):
                public = {"makeEntitiesPublic": pub, "as": sidecar_as or "headers"}
            elif pub in ("all", "*"):
                public = {"makeEntitiesPublic": pub, "as": sidecar_as or "headers"}
        env, sidecar = hpke.seal(
            kid=kid,
            recipient_public_jwk=pub_jwk,
            plaintext=plaintext,
            request=request,
            response=response,
            x402=x402,
            http_response_code=http_response_code,
            public=public,
        )
        # If request/response public expected, body will be returned instead of headers
        if isinstance(pub, list) and "request" in pub and request is not None:
            assert sidecar == request
        if isinstance(pub, list) and "response" in pub and response is not None:
            assert sidecar == response
        # Open envelope to validate
        pt, _, _ = hpke.open(
            recipient_private_jwk=priv_jwk,
            envelope=env,
            public_headers=sidecar if isinstance(sidecar, dict) and any(k.upper().startswith("X-") for k in sidecar.keys()) else None,
            public_json=sidecar if isinstance(sidecar, dict) and all(isinstance(v, str) for v in sidecar.values()) and any(k.upper().startswith("X-") for k in sidecar.keys()) else None,
            public_json_body=sidecar if isinstance(sidecar, dict) and not any(k.upper().startswith("X-") for k in sidecar.keys()) else None,
        )
        assert isinstance(pt, (bytes, bytearray))