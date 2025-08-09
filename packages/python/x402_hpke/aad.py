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


def build_canonical_aad(namespace: str, x402: Dict[str, Any], app: Optional[Dict[str, Any]] = None) -> Tuple[bytes, Dict[str, Any], Optional[Dict[str, Any]]]:
    if not namespace or namespace.lower() == "x402":
        raise NsForbidden("NS_FORBIDDEN")
    xv = validate_x402_core(x402)
    # app normalization with extensions
    app_norm: Optional[Dict[str, Any]] = None
    if app:
        if "x402" in app or any(str(k).lower().startswith("x402") for k in app.keys()):
            raise NsCollision("NS_COLLISION")
        copy: Dict[str, Any] = dict(app)
        exts = copy.get("extensions")
        if isinstance(exts, list):
            seen = set()
            norm_exts: List[Dict[str, Any]] = []
            for e in exts:
                hdr = str((e or {}).get("header") or "")
                if not is_approved_extension_header(hdr):
                    raise ValueError("X402_EXTENSION_UNAPPROVED")
                canon_hdr = canonicalize_extension_header(hdr)
                if canon_hdr.lower() in seen:
                    raise ValueError("X402_EXTENSION_DUPLICATE")
                payload = (e or {}).get("payload")
                if not isinstance(payload, dict) or len(payload.keys()) == 0:
                    raise ValueError("X402_EXTENSION_PAYLOAD")
                ext_obj = {"header": canon_hdr, "payload": payload}
                for k, v in (e or {}).items():
                    if k in ("header", "payload"):
                        continue
                    ext_obj[k] = v
                norm_exts.append(_deep_canonicalize(ext_obj))
                seen.add(canon_hdr.lower())
            norm_exts.sort(key=lambda x: x.get("header", "").lower())
            copy["extensions"] = norm_exts
        app_norm = json.loads(_canonical_json(copy))
    x_json = _canonical_json(xv)
    app_json = _canonical_json(app_norm) if app_norm else ""
    prefix = f"{namespace}|v1|"
    suffix = f"|{app_json}" if app else "|"
    full = prefix + x_json + suffix
    return full.encode("utf-8"), json.loads(x_json), app_norm


def canonical_aad(namespace: str, x402: Dict[str, Any], app: Optional[Dict[str, Any]] = None) -> bytes:
    return build_canonical_aad(namespace, x402, app)[0] 