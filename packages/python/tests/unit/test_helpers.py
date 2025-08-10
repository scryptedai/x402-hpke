from x402_hpke import create_hpke, create_payment_required
from x402_hpke.keys import generate_keypair

def test_create_payment_required_private():
    hpke = create_hpke(namespace="myapp")
    pub, priv = generate_keypair()
    payment_required_data = {"cost": "1000", "currency": "USD"}
    plaintext = b"hello"

    env, body = create_payment_required(
        hpke,
        payment_required_data=payment_required_data,
        recipient_public_jwk=pub,
        plaintext=plaintext,
        kid="server-key-1",
    )

    assert env is not None
    assert body is None

    pt, _, res, _, _ = hpke.open(
        recipient_private_jwk=priv,
        envelope=env,
        expected_kid="server-key-1",
    )

    assert pt == plaintext
    assert res == payment_required_data

def test_create_payment_required_public():
    hpke = create_hpke(namespace="myapp")
    pub, priv = generate_keypair()
    payment_required_data = {"cost": "1000", "currency": "USD"}
    plaintext = b"hello"

    env, body = create_payment_required(
        hpke,
        payment_required_data=payment_required_data,
        recipient_public_jwk=pub,
        plaintext=plaintext,
        kid="server-key-1",
        is_public=True,
    )

    assert env is not None
    assert body == payment_required_data

    pt, _, res, _, _ = hpke.open(
        recipient_private_jwk=priv,
        envelope=env,
        expected_kid="server-key-1",
    )

    assert pt == plaintext
    assert res == payment_required_data