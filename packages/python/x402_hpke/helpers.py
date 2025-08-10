import json
from typing import Dict, Any, Tuple, Optional, List
from .envelope import create_hpke
from .secure_transport import x402SecureTransport, TransportType
from .constants import CanonicalHeaders

def create_payment_required(
    hpke: object,
    payment_required_data: Dict[str, Any],
    recipient_public_jwk: Dict[str, Any],
    kid: str,
    is_public: bool = False,
) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    """
    A helper to create a 402 Payment Required response.
    """
    transport = x402SecureTransport(TransportType.PAYMENT_REQUIRED, payment_required_data)
    env, sidecar = hpke.seal(
        transport=transport,
        make_entities_public="all" if is_public else None,
        recipient_public_jwk=recipient_public_jwk,
        kid=kid,
    )
    return env, sidecar if is_public else None

def create_payment(
    hpke: object,
    payment_data: Dict[str, Any],
    recipient_public_jwk: Dict[str, Any],
    kid: str,
    extensions: Optional[List[Dict[str, Any]]] = None,
    is_public: bool = False,
) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    """
    A helper to create a client-side X-Payment request.
    """
    ext_pairs = [{"header": e.get("header"), "value": e.get("payload")} for e in (extensions or [])]
    transport = x402SecureTransport(TransportType.PAYMENT, {"payload": payment_data}, None, ext_pairs)
    return hpke.seal(
        transport=transport,
        make_entities_public=[CanonicalHeaders["X_PAYMENT"]] if is_public else None,
        recipient_public_jwk=recipient_public_jwk,
        kid=kid,
    )

def create_payment_response(
    hpke: object,
    settlement_data: Dict[str, Any],
    recipient_public_jwk: Dict[str, Any],
    kid: str,
    extensions: Optional[List[Dict[str, Any]]] = None,
    is_public: bool = False,
) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    """
    A helper to create a server-side X-Payment-Response.
    """
    ext_pairs = [{"header": e.get("header"), "value": e.get("payload")} for e in (extensions or [])]
    transport = x402SecureTransport(TransportType.PAYMENT_RESPONSE, settlement_data, 200, ext_pairs)
    return hpke.seal(
        transport=transport,
        make_entities_public=[CanonicalHeaders["X_PAYMENT_RESPONSE"]] if is_public else None,
        recipient_public_jwk=recipient_public_jwk,
        kid=kid,
    )

def create_request(
    hpke: object,
    request_data: Dict[str, Any],
    recipient_public_jwk: Dict[str, Any],
    kid: str,
    extensions: Optional[List[Dict[str, Any]]] = None,
    is_public: bool = False,
) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    """
    A helper to create a general-purpose request envelope.
    """
    ext_pairs = [{"header": e.get("header"), "value": e.get("payload")} for e in (extensions or [])]
    transport = x402SecureTransport(TransportType.OTHER_REQUEST, request_data, None, ext_pairs)
    env, sidecar = hpke.seal(
        transport=transport,
        make_entities_public="all" if is_public else None,
        recipient_public_jwk=recipient_public_jwk,
        kid=kid,
    )
    # Do not return public body from helper; align with Node helper behavior
    return env, None

def create_response(
    hpke: object,
    response_data: Dict[str, Any],
    recipient_public_jwk: Dict[str, Any],
    http_response_code: int,
    kid: str,
    extensions: Optional[List[Dict[str, Any]]] = None,
    is_public: bool = False,
) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    """
    A helper to create a general-purpose response envelope.
    """
    ext_pairs = [{"header": e.get("header"), "value": e.get("payload")} for e in (extensions or [])]
    transport = x402SecureTransport(TransportType.OTHER_RESPONSE, response_data, http_response_code, ext_pairs)
    env, sidecar = hpke.seal(
        transport=transport,
        make_entities_public="all" if is_public else None,
        recipient_public_jwk=recipient_public_jwk,
        kid=kid,
    )
    # Do not return public body from helper; align with Node helper behavior
    return env, None