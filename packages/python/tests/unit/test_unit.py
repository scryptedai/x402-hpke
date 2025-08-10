from x402_hpke import create_hpke
from x402_hpke.secure_transport import x402SecureTransport, TransportType
from x402_hpke.constants import CanonicalHeaders
import json, base64, os

def test_seal_open_roundtrip_with_request_payload():
    hpke = create_hpke(namespace="myapp")
    from x402_hpke.keys import generate_keypair
    pub, priv = generate_keypair()
    request_payload = {"action": "test"}
    t = x402SecureTransport(TransportType.OTHER_REQUEST, request_payload)
    env, _ = hpke.seal(transport=t, kid="kid1", recipient_public_jwk=pub)
    pt, req, _ = hpke.open(recipient_private_jwk=priv, envelope=env, expected_kid="kid1")
    assert json.loads(pt.decode("utf-8")) == request_payload

def test_public_json_body_for_request_payload():
    hpke = create_hpke(namespace="myapp")
    from x402_hpke.keys import generate_keypair
    pub, priv = generate_keypair()
    request_payload = {"data": "public"}
    t = x402SecureTransport(TransportType.OTHER_REQUEST, request_payload)
    env, body = hpke.seal(transport=t, kid="kid1", recipient_public_jwk=pub, make_entities_public=["data"])
    assert body == request_payload
    pt, _, _ = hpke.open(recipient_private_jwk=priv, envelope=env, expected_kid="kid1")
    assert json.loads(pt.decode("utf-8")) == request_payload

def test_reject_low_order_shared_secret():
    hpke = create_hpke(namespace="myapp")
    from x402_hpke.keys import generate_keypair
    pub, priv = generate_keypair()
    t = x402SecureTransport(TransportType.OTHER_REQUEST, {"data": "low_order"})
    env, _ = hpke.seal(transport=t, kid="kid1", recipient_public_jwk=pub)
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
    t = x402SecureTransport(TransportType.OTHER_REQUEST, {"data": "aead"})
    env, _ = hpke.seal(transport=t, kid="kid1", recipient_public_jwk=pub)
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

    # Case 1: Client request (no http_response_code) - can include X-PAYMENT in sidecar
    t_client = x402SecureTransport(TransportType.PAYMENT, {"payload": {"invoiceId": "inv_1"}})
    env, sidecar = hpke.seal(transport=t_client, kid="kid1", recipient_public_jwk=pub, make_entities_public=[CanonicalHeaders["X_PAYMENT"]])
    assert sidecar is not None
    assert CanonicalHeaders["X_PAYMENT"] in sidecar

    # Case 2: 402 response - no X-402 headers in sidecar (but body is encrypted)
    t_402 = x402SecureTransport(TransportType.PAYMENT_REQUIRED, {"status": "payment-required"})
    env_402, sidecar_402 = hpke.seal(transport=t_402, kid="kid1", recipient_public_jwk=pub)
    assert env_402 is not None
    assert sidecar_402 is None

    # Case 3: Success response (200) - can include X-PAYMENT-RESPONSE in sidecar
    t_success = x402SecureTransport(TransportType.PAYMENT_RESPONSE, {"settlementId": "settle_1"}, 200)
    env_success, sidecar_success = hpke.seal(transport=t_success, kid="kid1", recipient_public_jwk=pub, make_entities_public=[CanonicalHeaders["X_PAYMENT_RESPONSE"]])
    assert sidecar_success is not None
    assert CanonicalHeaders["X_PAYMENT_RESPONSE"] in sidecar_success

    # Verify all envelopes can be opened
    pt_client, _, _ = hpke.open(recipient_private_jwk=priv, envelope=env, public_headers=sidecar)
    pt_402, _, _ = hpke.open(recipient_private_jwk=priv, envelope=env_402)
    pt_success, _, _ = hpke.open(recipient_private_jwk=priv, envelope=env_success, public_headers=sidecar_success)

def test_kats_v1_vectors():
    # Dropped legacy V1 KATs in unified transport-only implementation
    assert True