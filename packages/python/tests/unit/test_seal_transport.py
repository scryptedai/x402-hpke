import json
import pytest
from x402_hpke.envelope import create_hpke
from x402_hpke.secure_transport import x402SecureTransport, TransportType
from x402_hpke.constants import CanonicalHeaders


def test_seal_transport_private_by_default(no_jwk_pair=None):
    hpke = create_hpke(namespace="myapp")
    # local JWKs
    from x402_hpke.keys import generate_keypair
    pub, priv = generate_keypair()
    t = x402SecureTransport(TransportType.OTHER_REQUEST, {"a": 1})
    envelope, sidecar = hpke.seal(kid="kid1", recipient_public_jwk=pub, transport=t)  # type: ignore[arg-type]
    assert envelope
    assert sidecar is None
    pt, body, headers = hpke.open(recipient_private_jwk=priv, envelope=envelope)
    assert json.loads(pt.decode("utf-8")) == {"a": 1}


def test_seal_transport_all_public_headers_and_body():
    hpke = create_hpke(namespace="myapp")
    from x402_hpke.keys import generate_keypair
    pub, priv = generate_keypair()
    t = x402SecureTransport(TransportType.PAYMENT, {"payload": {"invoiceId": "inv_1"}}, None, [
        {"header": "X-Ext", "value": {"foo": "bar"}},
    ])
    envelope, sidecar = hpke.seal(kid="kid1", recipient_public_jwk=pub, transport=t, make_entities_public="all")  # type: ignore[arg-type]
    assert isinstance(sidecar, dict)
    assert CanonicalHeaders["X_PAYMENT"] in sidecar
    assert "X-Ext" in sidecar
    pt, body, headers = hpke.open(recipient_private_jwk=priv, envelope=envelope, public_headers=sidecar)
    assert pt


def test_seal_transport_list_selection_headers_and_body():
    hpke = create_hpke(namespace="myapp")
    from x402_hpke.keys import generate_keypair
    pub, priv = generate_keypair()
    t = x402SecureTransport(TransportType.OTHER_RESPONSE, {"a": 1, "b": 2}, 200, [
        {"header": "X-Alpha", "value": {"A": True}},
        {"header": "X-Beta", "value": {"B": True}},
    ])
    envelope, sidecar = hpke.seal(kid="kid1", recipient_public_jwk=pub, transport=t, make_entities_public=["X-Alpha", "b"])  # type: ignore[arg-type]
    assert isinstance(sidecar, dict)
    assert sidecar == {"X-Alpha": "{\"A\":true}", "b": 2}
    pt, body, headers = hpke.open(recipient_private_jwk=priv, envelope=envelope, public_headers={"X-Alpha": sidecar["X-Alpha"]}, public_body={"b": 2})
    assert json.loads(pt.decode("utf-8")) == {"a": 1, "b": 2}


def test_seal_transport_402_suppresses_core_headers():
    hpke = create_hpke(namespace="myapp")
    from x402_hpke.keys import generate_keypair
    pub, priv = generate_keypair()
    t = x402SecureTransport(TransportType.PAYMENT_REQUIRED, {"need": True})
    envelope, sidecar = hpke.seal(kid="kid1", recipient_public_jwk=pub, transport=t, make_entities_public="all")  # type: ignore[arg-type]
    assert isinstance(sidecar, dict)
    assert CanonicalHeaders["X_PAYMENT"] not in sidecar and CanonicalHeaders["X_PAYMENT_RESPONSE"] not in sidecar
    assert sidecar.get("need") is True
    pt, body, headers = hpke.open(recipient_private_jwk=priv, envelope=envelope, public_body={"need": True})
    assert json.loads(pt.decode("utf-8")) == {"need": True}


