from x402_hpke import create_hpke
import json, base64, os

def test_seal_open_roundtrip():
    hpke = create_hpke(namespace="myapp")
    # dummy keys (generate both sides to simulate)
    from x402_hpke.keys import generate_keypair
    pub, priv = generate_keypair()
    x402 = {"header": "X-Payment", "payload": {"invoiceId": "inv_1"}}
    payload = b"hello"
    env, _ = hpke.seal(kid="kid1", recipient_public_jwk=pub, plaintext=payload, x402=x402)
    pt, x, app = hpke.open(recipient_private_jwk=priv, envelope=env, expected_kid="kid1")
    assert pt == payload
    assert x["header"] == "X-Payment"


def test_reject_low_order_shared_secret():
    hpke = create_hpke(namespace="myapp")
    from x402_hpke.keys import generate_keypair
    pub, priv = generate_keypair()
    x402 = {"header": "X-Payment", "payload": {"invoiceId": "inv_1"}}
    # Craft an envelope with enc = all-zero (invalid/low-order surrogate)
    payload = b"hi"
    env, _ = hpke.seal(kid="kid1", recipient_public_jwk=pub, plaintext=payload, x402=x402)
    env_bad = dict(env)
    import base64
    enc_zero = base64.urlsafe_b64encode(b"\x00"*32).decode("ascii").rstrip("=")
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
    x402 = {"header": "X-Payment", "payload": {"invoiceId": "inv_aead"}}
    payload = b"ok"
    env, _ = hpke.seal(kid="kid1", recipient_public_jwk=pub, plaintext=payload, x402=x402)
    bad = dict(env)
    bad["aead"] = "AES-256-GCM"
    try:
        hpke.open(recipient_private_jwk=priv, envelope=bad, expected_kid="kid1")
        assert False
    except ValueError as e:
        assert str(e) == "AEAD_MISMATCH"


def test_kats_if_present():
    kat_path = os.path.join(os.getcwd(), "docs", "KATs", "kat_v1.json")
    if not os.path.exists(kat_path):
        return
    with open(kat_path, "r", encoding="utf-8") as f:
        kat = json.load(f)
    for vector in kat.get("vectors", []):
        hpke = create_hpke(namespace=vector["ns"]) 
        from x402_hpke.keys import generate_keypair
        pub, priv = generate_keypair()
        pt = base64.urlsafe_b64decode(vector["plaintext_b64u"] + "==")
        kwargs = {
            "kid": vector["kid"],
            "recipient_public_jwk": pub,
            "plaintext": pt,
            "x402": vector.get("x402", {"header": "X-Payment", "payload": {"compat": True}}),
        }
        if vector.get("app"):
            kwargs["app"] = vector["app"]
    if vector.get("allowlist") or vector.get("sidecar_as"):
        kwargs["public"] = {"makeEntitiesPublic": ["X-PAYMENT"], "as": vector.get("sidecar_as", "headers")}
        env, sidecar = hpke.seal(**kwargs)
        if sidecar:
            pt2, _, _ = hpke.open(recipient_private_jwk=priv, envelope=env, expected_kid=vector["kid"], public_headers=sidecar if isinstance(sidecar, dict) else None, public_json=sidecar if isinstance(sidecar, dict) else None)
            assert pt2 == pt
        else:
            pt2, _, _ = hpke.open(recipient_private_jwk=priv, envelope=env, expected_kid=vector["kid"])
            assert pt2 == pt


def test_streaming_kats_if_present():
    kat_path = os.path.join(os.getcwd(), "docs", "KATs", "kat_stream_v1.json")
    if not os.path.exists(kat_path):
        return
    from x402_hpke import seal_chunk_xchacha, open_chunk_xchacha
    with open(kat_path, "r", encoding="utf-8") as f:
        kat = json.load(f)
    for v in kat.get("vectors", []):
        key = base64.urlsafe_b64decode(v["key_b64u"] + "==")
        prefix = base64.urlsafe_b64decode(v["prefix16_b64u"] + "==")
        aad = base64.urlsafe_b64decode(v["aad_b64u"] + "==") if v.get("aad_b64u") else None
        plains = [base64.urlsafe_b64decode(b64 + "==") for b64 in v["chunks_b64u"]]
        seq = int(v.get("start_seq", 0))
        cts = [seal_chunk_xchacha(key, prefix, seq + i, chunk, aad) for i, chunk in enumerate(plains)]
        for i, ct in enumerate(cts):
            pt = open_chunk_xchacha(key, prefix, seq + i, ct, aad)
            assert pt == plains[i]


def test_negative_kats_if_present():
    kat_path = os.path.join(os.getcwd(), "docs", "KATs", "kat_v1_negative.json")
    if not os.path.exists(kat_path):
        return
    with open(kat_path, "r", encoding="utf-8") as f:
        kat = json.load(f)
    for v in kat.get("vectors", []):
        hpke = create_hpke(namespace=v["ns"]) 
        from x402_hpke.keys import generate_keypair
        pub, priv = generate_keypair()
        pt = base64.urlsafe_b64decode(v["plaintext_b64u"] + "==")
        kwargs = {
            "kid": v["kid"],
            "recipient_public_jwk": pub,
            "plaintext": pt,
            "x402": v.get("x402", {"header": "X-Payment", "payload": {"compat": True}}),
        }
        if v.get("app"):
            kwargs["app"] = v["app"]
    if v.get("allowlist"):
        kwargs["public"] = {"makeEntitiesPublic": ["X-PAYMENT"], "as": "headers"}
        try:
            create_hpke(namespace=v["ns"]).seal(**kwargs)
            assert False
        except Exception as e:
            assert v["expected_error"] in str(e)


def test_core_requires_header_and_payload():
    hpke = create_hpke(namespace="myapp")
    from x402_hpke.keys import generate_keypair
    pub, priv = generate_keypair()
    try:
        hpke.seal(kid="kid1", recipient_public_jwk=pub, plaintext=b"x", x402={})
        assert False
    except Exception as e:
        assert "X402_HEADER" in str(e) or "X402_PAYLOAD" in str(e)


def test_payment_sidecar_roundtrip():
    hpke = create_hpke(namespace="myapp")
    from x402_hpke.keys import generate_keypair
    pub, priv = generate_keypair()
    env, sidecar = hpke.seal(kid="kid1", recipient_public_jwk=pub, plaintext=b"ok", x402={"header": "X-Payment", "payload": {"invoiceId": "inv"}}, public={"makeEntitiesPublic": ["X-PAYMENT"], "as": "headers"})
    pt, x, _ = hpke.open(recipient_private_jwk=priv, envelope=env, expected_kid="kid1", public_headers=sidecar)
    assert pt == b"ok"


def test_three_use_cases_for_sidecar_generation():
    hpke = create_hpke(namespace="myapp")
    from x402_hpke.keys import generate_keypair
    pub, priv = generate_keypair()
    x402 = {"header": "X-Payment", "payload": {"invoiceId": "inv_1"}}
    payload = b"test data"

    # Case 1: Client request (no http_response_code) - can include X-PAYMENT in sidecar
    env, sidecar = hpke.seal(
        kid="kid1",
        recipient_public_jwk=pub,
        plaintext=payload,
        x402=x402,
        public={"makeEntitiesPublic": ["X-PAYMENT"], "as": "headers"}
    )
    assert sidecar is not None
    assert "X-PAYMENT" in sidecar
    
    # Case 2: 402 response - no X-402 headers in sidecar (but body is encrypted)
    env_402, sidecar_402 = hpke.seal(
        kid="kid1",
        recipient_public_jwk=pub,
        plaintext=payload,
        x402=x402,
        http_response_code=402,
        public={"makeEntitiesPublic": ["X-PAYMENT"], "as": "headers"}  # This should be ignored for 402
    )
    assert env_402 is not None
    assert sidecar_402 is None  # 402 responses don't send X-402 headers
    
    # Case 3: Success response (200) - can include X-PAYMENT-RESPONSE in sidecar
    x402_response = {"header": "X-Payment-Response", "payload": {"settlementId": "settle_1"}}
    env_success, sidecar_success = hpke.seal(
        kid="kid1",
        recipient_public_jwk=pub,
        plaintext=payload,
        x402=x402_response,
        http_response_code=200,
        public={"makeEntitiesPublic": ["X-PAYMENT-RESPONSE"], "as": "headers"}
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