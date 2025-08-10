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

    env, body = create_payment_required(
        hpke,
        payment_required_data=payment_required_data,
        recipient_public_jwk=pub,
        kid="server-key-1",
    )
    assert env is not None
    assert body is None
    pt, response, _ = hpke.open(
        recipient_private_jwk=priv,
        envelope=env,
        expected_kid="server-key-1",
    )
    expected_plaintext = json.dumps(payment_required_data).encode("utf-8")
    assert pt == expected_plaintext
    assert response == payment_required_data


def test_create_payment_required_public():
    hpke = create_hpke(namespace="myapp")
    pub, priv = generate_keypair()
    payment_required_data = {"cost": "1000", "currency": "USD"}

    env, body = create_payment_required(
        hpke,
        payment_required_data=payment_required_data,
        recipient_public_jwk=pub,
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
    expected_plaintext = json.dumps(payment_required_data).encode("utf-8")
    assert pt == expected_plaintext
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
    expected_plaintext = json.dumps({"header": "X-Payment", "payload": payment_data}).encode("utf-8")
    assert pt == expected_plaintext
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
    )
    expected_plaintext = json.dumps({"header": "X-Payment", "payload": payment_data}).encode("utf-8")
    assert pt == expected_plaintext
    assert x402["payload"] == payment_data


def test_create_payment_response():
    hpke = create_hpke(namespace="myapp")
    pub, priv = generate_keypair()
    settlement_data = {"settlementId": "settle_123"}

    # Private by default
    env, headers = create_payment_response(
        hpke,
        settlement_data=settlement_data,
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
    expected_plaintext = json.dumps({"header": "X-Payment-Response", "payload": settlement_data}).encode("utf-8")
    assert pt == expected_plaintext
    assert x402["payload"] == settlement_data

    # Public
    env, headers = create_payment_response(
        hpke,
        settlement_data=settlement_data,
        recipient_public_jwk=pub,
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
    )
    expected_plaintext = json.dumps({"header": "X-Payment-Response", "payload": settlement_data}).encode("utf-8")
    assert pt == expected_plaintext
    assert x402["payload"] == settlement_data


def test_create_request():
    hpke = create_hpke(namespace="myapp")
    pub, priv = generate_keypair()
    request_data = {"action": "getData", "params": {"id": 123}}

    # Private by default
    env, headers = create_request(
        hpke,
        request_data=request_data,
        recipient_public_jwk=pub,
        kid="server-key-1",
    )
    assert env is not None
    assert headers is None
    pt, request, _ = hpke.open(
        recipient_private_jwk=priv,
        envelope=env,
        expected_kid="server-key-1",
    )
    expected_plaintext = json.dumps(request_data).encode("utf-8")
    assert pt == expected_plaintext
    assert request == request_data

    # Public
    env, headers = create_request(
        hpke,
        request_data=request_data,
        recipient_public_jwk=pub,
        kid="server-key-1",
        is_public=True,
    )
    assert env is not None
    # Generic request bodies are not emitted as headers; optional JSON body may be returned by direct seal
    assert headers is None
    pt, request, _ = hpke.open(
        recipient_private_jwk=priv,
        envelope=env,
        expected_kid="server-key-1",
    )
    expected_plaintext = json.dumps(request_data).encode("utf-8")
    assert pt == expected_plaintext
    assert request == request_data


def test_create_response():
    hpke = create_hpke(namespace="myapp")
    pub, priv = generate_keypair()
    response_data = {"status": "success", "data": {"result": "ok"}}

    # Private by default
    env, headers = create_response(
        hpke,
        response_data=response_data,
        recipient_public_jwk=pub,
        http_response_code=200,
        kid="server-key-1",
    )
    assert env is not None
    assert headers is None
    pt, response, _ = hpke.open(
        recipient_private_jwk=priv,
        envelope=env,
        expected_kid="server-key-1",
    )
    expected_plaintext = json.dumps(response_data).encode("utf-8")
    assert pt == expected_plaintext
    assert response == response_data

    # Public
    env, headers = create_response(
        hpke,
        response_data=response_data,
        recipient_public_jwk=pub,
        http_response_code=200,
        kid="server-key-1",
        is_public=True,
    )
    assert env is not None
    # Generic responses are not emitted as headers; optional JSON body may be returned by direct seal
    assert headers is None
    pt, response, _ = hpke.open(
        recipient_private_jwk=priv,
        envelope=env,
        expected_kid="server-key-1",
    )
    expected_plaintext = json.dumps(response_data).encode("utf-8")
    assert pt == expected_plaintext
    assert response == response_data