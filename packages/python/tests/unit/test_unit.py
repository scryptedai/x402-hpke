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
    pt, req, _, _, _ = hpke.open(recipient_private_jwk=priv, envelope=env, expected_kid="kid1")
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
    pt, _, _, _, _ = hpke.open(recipient_private_jwk=priv, envelope=env, expected_kid="kid1")
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
        x402={"header": "", "payload": {}},
        http_response_code=402,
        kid="kid1",
        recipient_public_jwk=pub,
        plaintext=payload,
        public={"makeEntitiesPublic": ["X-Payment"], "as": "headers"},  # This should be ignored for 402
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
    pt_client, _, _, _, _ = hpke.open(recipient_private_jwk=priv, envelope=env, public_headers=sidecar)
    pt_402, _, _, _, _ = hpke.open(recipient_private_jwk=priv, envelope=env_402)
    pt_success, _, _, _, _ = hpke.open(recipient_private_jwk=priv, envelope=env_success, public_headers=sidecar_success)

    assert pt_client == payload
    assert pt_402 == payload
    assert pt_success == payload

# Remove KAT tests for now as they are based on the old API
# The KAT files themselves will need to be updated to reflect the new payload structure.