import json
import re
from typing import Any, Dict, Tuple, Optional
from .errors import NsForbidden, NsCollision, X402Error, ReplyToMissing, ReplyToFormat


def _normalize_hex(s: str, expected_len: Optional[int] = None) -> str:
    if not isinstance(s, str):
        raise X402Error("X402_SCHEMA")
    s = s.lower()
    if not s.startswith("0x"):
        raise X402Error("X402_SCHEMA")
    if not re.fullmatch(r"0x[0-9a-f]+", s):
        raise X402Error("X402_SCHEMA")
    if expected_len and len(s) != 2 + expected_len:
        raise X402Error("X402_SCHEMA")
    return s


def _validate_amount(amount: str) -> str:
    if not isinstance(amount, str):
        raise X402Error("X402_SCHEMA")
    if not re.fullmatch(r"(0|[1-9][0-9]*)", amount):
        raise X402Error("X402_SCHEMA")
    return amount


def validate_x402(x: Dict[str, Any]) -> Dict[str, Any]:
    v = {
        "invoiceId": str(x.get("invoiceId", "")),
        "chainId": int(x.get("chainId")),
        "tokenContract": _normalize_hex(str(x.get("tokenContract", "")), 40),
        "amount": _validate_amount(str(x.get("amount", ""))),
        "recipient": _normalize_hex(str(x.get("recipient", "")), 40),
        "txHash": _normalize_hex(str(x.get("txHash", "")), 64),
        "expiry": int(x.get("expiry")),
        "priceHash": _normalize_hex(str(x.get("priceHash", "")), 64),
        "replyToJwks": str(x.get("replyToJwks")) if x.get("replyToJwks") else None,
        "replyToKid": str(x.get("replyToKid")) if x.get("replyToKid") else None,
        "replyToJwk": x.get("replyToJwk"),
        "replyPublicOk": bool(x.get("replyPublicOk")) if x.get("replyPublicOk") is not None else None,
    }
    if not v["invoiceId"]:
        raise X402Error("X402_SCHEMA")
    # Enforce reply-to presence and format
    has_jwks = bool(v.get("replyToJwks")) and bool(v.get("replyToKid"))
    rjwk = v.get("replyToJwk")
    has_jwk = bool(rjwk) and isinstance(rjwk, dict) and rjwk.get("kty") == "OKP" and rjwk.get("crv") == "X25519" and isinstance(rjwk.get("x"), str)
    if not has_jwks and not has_jwk:
        raise ReplyToMissing("REPLY_TO_REQUIRED")
    if v.get("replyToJwks") and not str(v["replyToJwks"]).startswith("https://"):
        raise ReplyToFormat("REPLY_TO_JWKS_HTTPS_REQUIRED")
    return v


def _canonical_json(obj: Dict[str, Any]) -> str:
    return json.dumps({k: obj[k] for k in sorted(obj.keys())}, separators=(",", ":"))


def build_canonical_aad(namespace: str, x402: Dict[str, Any], app: Optional[Dict[str, Any]] = None) -> Tuple[bytes, Dict[str, Any], Optional[Dict[str, Any]]]:
    if not namespace or namespace.lower() == "x402":
        raise NsForbidden("NS_FORBIDDEN")
    xv = validate_x402(x402)
    if app:
        for k in app.keys():
            if k == "x402" or k.startswith("x402") or k in xv:
                raise NsCollision("NS_COLLISION")
    x_json = _canonical_json(xv)
    app_json = _canonical_json(app) if app else ""
    prefix = f"{namespace}|v1|"
    suffix = f"|{app_json}" if app else "|"
    full = prefix + x_json + suffix
    return full.encode("utf-8"), xv, (json.loads(app_json) if app else None)


def canonical_aad(namespace: str, x402: Dict[str, Any], app: Optional[Dict[str, Any]] = None) -> bytes:
    return build_canonical_aad(namespace, x402, app)[0] 