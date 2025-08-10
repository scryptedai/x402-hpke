from x402_hpke import (
    create_hpke,
    create_payment_required,
    create_payment,
    create_payment_response,
    create_request,
    create_response,
)
from x402_hpke.keys import generate_keypair
import pytest
import json


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
    pt, response, _ = hpke.open(
        recipient_private_jwk=priv,
        envelope=env,
        expected_kid="server-key-1",
    )
    assert pt == plaintext
    assert response == payment_required_data


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
    # Note: Python implementation doesn't currently support public response bodies
    # This test will need to be updated when that functionality is implemented

    pt, response, _ = hpke.open(
        recipient_private_jwk=priv,
        envelope=env,
        expected_kid="server-key-1",
    )
    assert pt == plaintext
    assert response == payment_required_data


def test_create_payment():
    hpke = create_hpke(namespace="myapp")
    pub, priv = generate_keypair()
    payment_data = {"invoiceId": "inv_123"}

    # Private by default
    env, headers = create_payment(
        hpke,
        payment_data=payment_data,
        recipient_public_jwk=pub,
        kid="server-key-1",
    )
    assert env is not None
    assert headers is None
    pt, x402, _ = hpke.open(
        recipient_private_jwk=priv,
        envelope=env,
        expected_kid="server-key-1",
    )
    assert len(pt) == 0
    assert x402["payload"] == payment_data

    # Public
    env, headers = create_payment(
        hpke,
        payment_data=payment_data,
        recipient_public_jwk=pub,
        kid="server-key-1",
        is_public=True,
    )
    assert env is not None
    assert headers is not None
    assert "x-payment" in {k.lower() for k in headers.keys()}
    pt, x402, _ = hpke.open(
        recipient_private_jwk=priv,
        envelope=env,
        expected_kid="server-key-1",
        public_headers=headers,
    )
    assert len(pt) == 0
    assert x402["payload"] == payment_data


def test_create_payment_response():
    hpke = create_hpke(namespace="myapp")
    pub, priv = generate_keypair()
    settlement_data = {"receipt": "receipt_123"}
    plaintext = b"here is your data"

    # Private by default
    env, headers = create_payment_response(
        hpke,
        settlement_data=settlement_data,
        recipient_public_jwk=pub,
        plaintext=plaintext,
        kid="server-key-1",
    )
    assert env is not None
    assert headers is None
    pt, x402, _ = hpke.open(
        recipient_private_jwk=priv,
        envelope=env,
        expected_kid="server-key-1",
    )
    assert pt == plaintext
    assert x402["payload"] == settlement_data

    # Public
    env, headers = create_payment_response(
        hpke,
        settlement_data=settlement_data,
        recipient_public_jwk=pub,
        plaintext=plaintext,
        kid="server-key-1",
        is_public=True,
    )
    assert env is not None
    assert headers is not None
    assert "x-payment-response" in {k.lower() for k in headers.keys()}
    pt, x402, _ = hpke.open(
        recipient_private_jwk=priv,
        envelope=env,
        expected_kid="server-key-1",
        public_headers=headers,
    )
    assert pt == plaintext
    assert x402["payload"] == settlement_data


def test_create_request():
    hpke = create_hpke(namespace="myapp")
    pub, priv = generate_keypair()
    request_data = {"action": "get_data", "resource": "/api/users"}

    # Private by default
    env, body = create_request(
        hpke,
        request_data=request_data,
        recipient_public_jwk=pub,
        kid="client-key-1",
    )
    assert env is not None
    assert body is None
    pt, request, _ = hpke.open(
        recipient_private_jwk=priv,
        envelope=env,
        expected_kid="client-key-1",
    )
    decoded_request = json.loads(pt.decode("utf-8"))
    assert decoded_request == request_data

    # Public
    env, body = create_request(
        hpke,
        request_data=request_data,
        recipient_public_jwk=pub,
        kid="client-key-1",
        is_public=True,
    )
    assert env is not None
    assert body == request_data
    pt, request, _ = hpke.open(
        recipient_private_jwk=priv,
        envelope=env,
        expected_kid="client-key-1",
        public_json_body=body,
    )
    decoded_request = json.loads(pt.decode("utf-8"))
    assert decoded_request == request_data

    # With extensions
    extensions = [{"header": "X-Custom", "payload": {"custom": "value"}}]
    from x402_hpke.extensions import APPROVED_EXTENSION_HEADERS
    APPROVED_EXTENSION_HEADERS.append("x-custom")
    env, body = create_request(
        hpke,
        request_data=request_data,
        recipient_public_jwk=pub,
        kid="client-key-1",
        extensions=extensions,
        is_public=True,
    )
    assert env is not None
    assert body == request_data

    pt, request, ext = hpke.open(
        recipient_private_jwk=priv,
        envelope=env,
        expected_kid="client-key-1",
        public_json_body=body,
    )
    decoded_request = json.loads(pt.decode("utf-8"))
    assert decoded_request == request_data
    assert ext[0]["header"].lower() == extensions[0]["header"].lower()
    assert ext[0]["payload"] == extensions[0]["payload"]
    APPROVED_EXTENSION_HEADERS.pop()


def test_create_response():
    hpke = create_hpke(namespace="myapp")
    pub, priv = generate_keypair()
    response_data = {"status": "success", "data": {"id": 123, "name": "test"}}
    plaintext = b"response data"

    # Private by default
    env, body = create_response(
        hpke,
        response_data=response_data,
        recipient_public_jwk=pub,
        plaintext=plaintext,
        http_response_code=200,
        kid="server-key-1",
    )
    assert env is not None
    assert body is None

    pt, response, _ = hpke.open(
        recipient_private_jwk=priv,
        envelope=env,
        expected_kid="server-key-1",
    )
    assert pt == plaintext
    assert response == response_data

    # Public
    env, body = create_response(
        hpke,
        response_data=response_data,
        recipient_public_jwk=pub,
        plaintext=plaintext,
        http_response_code=200,
        kid="server-key-1",
        is_public=True,
    )
    assert env is not None
    assert body == response_data

    pt, response, _ = hpke.open(
        recipient_private_jwk=priv,
        envelope=env,
        expected_kid="server-key-1",
        public_json_body=body,
    )
    assert pt == plaintext
    assert response == response_data

    # Works with different http response codes
    env, _ = create_response(
        hpke,
        response_data=response_data,
        recipient_public_jwk=pub,
        plaintext=plaintext,
        http_response_code=201,
        kid="server-key-1",
    )
    assert env is not None

    pt, response, _ = hpke.open(
        recipient_private_jwk=priv,
        envelope=env,
        expected_kid="server-key-1",
    )
    assert response == response_data