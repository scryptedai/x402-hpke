import json
from typing import Any, Dict, Tuple, Optional, List
from .errors import NsForbidden, NsCollision
from .extensions import is_approved_extension_header, canonicalize_extension_header


def _deep_canonicalize(obj: Any) -> Any:
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, list):
        return [_deep_canonicalize(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _deep_canonicalize(obj[k]) for k in sorted(obj.keys())}
    return obj


def _canonical_json(obj: Dict[str, Any]) -> str:
    return json.dumps(_deep_canonicalize(obj), separators=(",", ":"))


def _canonicalize_header_case(h: str) -> str:
    s = str(h or "").lower()
    if s == "x-payment":
        return "X-Payment"
    if s == "x-payment-response":
        return "X-Payment-Response"
    raise ValueError("X402_HEADER")

def validate_x402_core(x: Dict[str, Any]) -> Dict[str, Any]:
    header = _canonicalize_header_case((x or {}).get("header"))
    payload = (x or {}).get("payload")
    if not isinstance(payload, dict) or len(payload.keys()) == 0:
        raise ValueError("X402_PAYLOAD")
    out = {"header": header, "payload": payload}
    for k, v in (x or {}).items():
        if k in ("header", "payload"):
            continue
        out[k] = v
    return out


def build_canonical_aad(
    namespace: str,
    payload: Dict[str, Any],
    extensions: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[bytes, Optional[Dict[str, Any]], Optional[Dict[str, Any]], Optional[Dict[str, Any]], Optional[List[Dict[str, Any]]]]:
    if not namespace or namespace.lower() == "x402":
        raise NsForbidden("NS_FORBIDDEN")
    
    request = payload.get("request")
    response = payload.get("response")
    x402 = payload.get("x402")
    
    primary_json = ""
    x402_normalized, request_normalized, response_normalized = None, None, None

    if x402 is not None:
        x = validate_x402_core(x402)
        primary_json = _canonical_json(x)
        x402_normalized = json.loads(primary_json)
    elif request is not None:
        primary_json = _canonical_json(request)
        request_normalized = json.loads(primary_json)
    elif response is not None:
        primary_json = _canonical_json(response)
        response_normalized = json.loads(primary_json)

    extensions_normalized = None
    extensions_json = ""
    if extensions:
        seen = set()
        norm_exts: List[Dict[str, Any]] = []
        for e in extensions:
            hdr = str((e or {}).get("header") or "")
            if not is_approved_extension_header(hdr):
                raise ValueError("X402_EXTENSION_UNAPPROVED")
            canon_hdr = canonicalize_extension_header(hdr)
            if canon_hdr.lower() in seen:
                raise ValueError("X402_EXTENSION_DUPLICATE")
            ext_payload = (e or {}).get("payload")
            if not isinstance(ext_payload, dict) or len(ext_payload.keys()) == 0:
                raise ValueError("X402_EXTENSION_PAYLOAD")
            ext_obj = {"header": canon_hdr, "payload": ext_payload}
            for k, v in (e or {}).items():
                if k in ("header", "payload"):
                    continue
                ext_obj[k] = v
            norm_exts.append(_deep_canonicalize(ext_obj))
            seen.add(canon_hdr.lower())
        norm_exts.sort(key=lambda x: x.get("header", "").lower())
        extensions_normalized = norm_exts
        extensions_json = _canonical_json(extensions_normalized)
        
    prefix = f"{namespace}|v1|"
    suffix = f"|{extensions_json}" if extensions else "|"
    full = prefix + primary_json + suffix
    return (
        full.encode("utf-8"),
        x402_normalized,
        request_normalized,
        response_normalized,
        extensions_normalized,
    )


def canonical_aad(
    namespace: str,
    payload: Dict[str, Any],
    extensions: Optional[List[Dict[str, Any]]] = None,
) -> bytes:
    return build_canonical_aad(namespace, payload, extensions)[0] 