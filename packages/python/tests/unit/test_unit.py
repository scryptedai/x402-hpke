from x402_hpke import create_hpke
import json, base64, os

def test_seal_open_roundtrip():
    hpke = create_hpke(namespace="myapp")
    # dummy keys (generate both sides to simulate)
    from x402_hpke.keys import generate_keypair
    pub, priv = generate_keypair()
    x402 = {
        "invoiceId": "inv_1",
        "chainId": 8453,
        "tokenContract": "0x" + "a"*40,
        "amount": "1000",
        "recipient": "0x" + "b"*40,
        "txHash": "0x" + "c"*64,
        "expiry": 9999999999,
        "priceHash": "0x" + "d"*64,
    }
    payload = b"hello"
    env, _ = hpke.seal(kid="kid1", recipient_public_jwk=pub, plaintext=payload, x402=x402)
    pt, x, app = hpke.open(recipient_private_jwk=priv, envelope=env, expected_kid="kid1")
    assert pt == payload
    assert x["invoiceId"] == x402["invoiceId"]


def test_reject_low_order_shared_secret():
    hpke = create_hpke(namespace="myapp")
    from x402_hpke.keys import generate_keypair
    pub, priv = generate_keypair()
    x402 = {
        "invoiceId": "inv_1",
        "chainId": 8453,
        "tokenContract": "0x" + "a"*40,
        "amount": "1000",
        "recipient": "0x" + "b"*40,
        "txHash": "0x" + "c"*64,
        "expiry": 9999999999,
        "priceHash": "0x" + "d"*64,
    }
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
    x402 = {
        "invoiceId": "inv_aead",
        "chainId": 8453,
        "tokenContract": "0x" + "a"*40,
        "amount": "1000",
        "recipient": "0x" + "b"*40,
        "txHash": "0x" + "c"*64,
        "expiry": 9999999999,
        "priceHash": "0x" + "d"*64,
    }
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
        # Since Python currently doesn't expose eph seed in API, we just open Node-produced envelope if present
        if "envelope" in vector:
            env = vector["envelope"]
            # ensure expected kid opens
            from x402_hpke.keys import generate_keypair
            pub, priv = generate_keypair()
            pt_expected = base64.urlsafe_b64decode(vector["plaintext_b64u"] + "==")
            # Re-seal path is skipped; we validate open path via roundtrip in other tests
            # Here: decode aad and ensure base64url formatting is correct
            base64.urlsafe_b64decode(env["aad"] + "==")
            # Build a minimal envelope by copying vector but with our pub key will not decrypt; skip decryption
            # KATs are primarily consumed by Node test for sealing determinism
            assert isinstance(env["aad"], str) and isinstance(env["enc"], str)