from __future__ import annotations
from typing import Any, Dict, Optional, Tuple, TypedDict
import base64
import json


class XPaymentAuthorization(TypedDict):
    from_: str  # hex address; underscore to avoid keyword
    to: str
    value: str
    validAfter: str
    validBefore: str
    nonce: str


class XPaymentPayload(TypedDict):
    signature: str
    authorization: Dict[str, Any]


class XPaymentHeader(TypedDict):
    x402Version: int
    scheme: str
    network: str
    payload: XPaymentPayload


class XPaymentResponseHeader(TypedDict, total=False):
    x402Version: int
    scheme: str
    network: str
    payload: Dict[str, Any]


PaymentLike = Dict[str, Any]


def _deep_canonicalize(obj: Any) -> Any:
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, list):
        return [_deep_canonicalize(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _deep_canonicalize(obj[k]) for k in sorted(obj.keys())}
    return obj


def synthesize_payment_header_value(p: PaymentLike) -> str:
    # Emit compact, stable JSON string
    return json.dumps(_deep_canonicalize(p), separators=(",", ":"))


def parse_payment_header_value(s: str) -> Optional[PaymentLike]:
    # Accept raw JSON or base64-encoded JSON
    try:
        j = json.loads(s)
        return normalize_payment_like(j)
    except Exception:
        try:
            dec = base64.b64decode(s + "==").decode("utf-8")
            j2 = json.loads(dec)
            return normalize_payment_like(j2)
        except Exception:
            return None


def normalize_payment_like(p: PaymentLike) -> PaymentLike:
    if not isinstance(p, dict):
        raise ValueError("X_PAYMENT_SCHEMA")
    if p.get("x402Version") != 1:
        raise ValueError("X_PAYMENT_VERSION")
    if not isinstance(p.get("scheme"), str) or not isinstance(p.get("network"), str):
        raise ValueError("X_PAYMENT_SCHEMA")
    payload = p.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("X_PAYMENT_SCHEMA")
    # minimal checks only; leave deep chain-specific validation to integrators
    return p


def derive_extended_app_from_payment(p: PaymentLike) -> Dict[str, str]:
    try:
        auth = p.get("payload", {}).get("authorization", {})
        return {
            "paymentScheme": str(p.get("scheme")),
            "paymentNetwork": str(p.get("network")),
            "paymentFrom": str(auth.get("from")),
            "paymentTo": str(auth.get("to")),
            "paymentValue": str(auth.get("value")),
            "paymentValidAfter": str(auth.get("validAfter")),
            "paymentValidBefore": str(auth.get("validBefore")),
            "paymentNonce": str(auth.get("nonce")),
            "paymentSignature": str(p.get("payload", {}).get("signature")),
        }
    except Exception:
        return {}

