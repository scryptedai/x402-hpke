import pytest
from x402_hpke.secure_transport import x402SecureTransport, TransportType
from x402_hpke.constants import CanonicalHeaders


def test_other_request_rejects_http_code_and_maps_to_body():
    with pytest.raises(Exception):
        x402SecureTransport(TransportType.OTHER_REQUEST, {"a": 1}, 200)
    t = x402SecureTransport(TransportType.OTHER_REQUEST, {"a": 1})
    assert t.getHttpResponseCode() is None
    assert t.getBody() == {"a": 1}
    assert t.getHeader() is None
    assert t.getExtensions() == []


def test_other_response_rejects_402_accepts_200():
    with pytest.raises(Exception):
        x402SecureTransport(TransportType.OTHER_RESPONSE, {"ok": True}, 402)
    t = x402SecureTransport(TransportType.OTHER_RESPONSE, {"ok": True}, 200)
    assert t.getHttpResponseCode() == 200
    assert t.getBody() == {"ok": True}
    assert t.getHeader() is None


def test_payment_required_requires_non_empty_and_warns_then_sets_402(monkeypatch):
    with pytest.raises(Exception):
        x402SecureTransport(TransportType.PAYMENT_REQUIRED, {})

    warnings = []

    def fake_warn(msg):
        warnings.append(str(msg))

    monkeypatch.setattr("x402_hpke.secure_transport.warn", fake_warn)
    t = x402SecureTransport(TransportType.PAYMENT_REQUIRED, {"need": True}, 200)
    assert t.getHttpResponseCode() == 402
    assert any("PAYMENT_REQUIRED_HTTP_CODE_WARN" in s for s in warnings)
    assert t.getBody() == {"need": True}
    assert t.getHeader() is None


def test_payment_response_requires_non_empty_sets_200_and_rejects_mismatch():
    with pytest.raises(Exception):
        x402SecureTransport(TransportType.PAYMENT_RESPONSE, {})
    with pytest.raises(Exception):
        x402SecureTransport(TransportType.PAYMENT_RESPONSE, {"ok": True}, 204)
    t = x402SecureTransport(TransportType.PAYMENT_RESPONSE, {"ok": True})
    assert t.getHttpResponseCode() == 200
    assert t.getHeader() == {"header": CanonicalHeaders["X_PAYMENT_RESPONSE"], "value": {"ok": True}}
    assert t.getBody() == {}


def test_payment_requires_payload_rejects_http_code_and_maps_to_header():
    with pytest.raises(Exception):
        x402SecureTransport(TransportType.PAYMENT, {"not_payload": True})
    with pytest.raises(Exception):
        x402SecureTransport(TransportType.PAYMENT, {"payload": {"id": 1}}, 200)
    t = x402SecureTransport(TransportType.PAYMENT, {"payload": {"id": 1}})
    assert t.getHttpResponseCode() is None
    assert t.getHeader() == {"header": CanonicalHeaders["X_PAYMENT"], "value": {"payload": {"id": 1}}}
    assert t.getBody() == {}


def test_extensions_round_trip():
    exts = [
        {"header": "X-Example", "value": {"a": 1}},
        {"header": "X-Another", "value": "b"},
    ]
    t = x402SecureTransport(TransportType.OTHER_REQUEST, {"z": 1}, None, exts)
    assert t.getExtensions() == exts


