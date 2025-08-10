import json
from typing import Dict, Any, Tuple, Optional, List
from .envelope import create_hpke

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
    env, public_body = hpke.seal(
        response=payment_required_data,
        http_response_code=402,
        public={"makeEntitiesPublic": ["*"], "as": "json"} if is_public else None,
        recipient_public_jwk=recipient_public_jwk,
        kid=kid,
    )
    return env, public_body if is_public else None

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
    return hpke.seal(
        x402={
            "header": "X-Payment",
            "payload": payment_data,
        },
        public={"makeEntitiesPublic": ["X-Payment"]} if is_public else None,
        recipient_public_jwk=recipient_public_jwk,
        kid=kid,
        extensions=extensions,
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
    return hpke.seal(
        x402={
            "header": "X-Payment-Response",
            "payload": settlement_data,
        },
        http_response_code=200,
        public={"makeEntitiesPublic": ["X-Payment-Response"]} if is_public else None,
        recipient_public_jwk=recipient_public_jwk,
        kid=kid,
        extensions=extensions,
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
    return hpke.seal(
        request=request_data,
        public={"makeEntitiesPublic": ["request", *[e["header"] for e in extensions]]} if is_public and extensions else {"makeEntitiesPublic": ["request"]} if is_public else None,
        recipient_public_jwk=recipient_public_jwk,
        kid=kid,
        extensions=extensions,
    )

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
    return hpke.seal(
        response=response_data,
        http_response_code=http_response_code,
        public={"makeEntitiesPublic": ["response"]} if is_public else None,
        recipient_public_jwk=recipient_public_jwk,
        kid=kid,
        extensions=extensions,
    )