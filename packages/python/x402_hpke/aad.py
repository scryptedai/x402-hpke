import json
import re
from typing import Any, Dict, Tuple, Optional


def _normalize_hex(s: str, expected_len: Optional[int] = None) -> str:
    if not isinstance(s, str):
        raise ValueError("X402_SCHEMA")
    s = s.lower()
    if not s.startswith("0x"):
        raise ValueError("X402_SCHEMA")
    if not re.fullmatch(r"0x[0-9a-f]+", s):
        raise ValueError("X402_SCHEMA")
    if expected_len and len(s) != 2 + expected_len:
        raise ValueError("X402_SCHEMA")
    return s


def _validate_amount(amount: str) -> str:
    if not isinstance(amount, str):
        raise ValueError("X402_SCHEMA")
    if not re.fullmatch(r"(0|[1-9][0-9]*)", amount):
        raise ValueError("X402_SCHEMA")
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
    }
    if not v["invoiceId"]:
        raise ValueError("X402_SCHEMA")
    return v


def _canonical_json(obj: Dict[str, Any]) -> str:
    return json.dumps({k: obj[k] for k in sorted(obj.keys())}, separators=(",", ":"))


def build_canonical_aad(namespace: str, x402: Dict[str, Any], app: Optional[Dict[str, Any]] = None) -> Tuple[bytes, Dict[str, Any], Optional[Dict[str, Any]]]:
    if not namespace or namespace.lower() == "x402":
        raise ValueError("NS_FORBIDDEN")
    xv = validate_x402(x402)
    if app:
        for k in app.keys():
            if k == "x402" or k.startswith("x402") or k in xv:
                raise ValueError("NS_COLLISION")
    x_json = _canonical_json(xv)
    app_json = _canonical_json(app) if app else ""
    prefix = f"{namespace}|v1|"
    suffix = f"|{app_json}" if app else "|"
    full = prefix + x_json + suffix
    return full.encode("utf-8"), xv, (json.loads(app_json) if app else None)


def canonical_aad(namespace: str, x402: Dict[str, Any], app: Optional[Dict[str, Any]] = None) -> bytes:
    return build_canonical_aad(namespace, x402, app)[0] 