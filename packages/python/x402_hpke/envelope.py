from __future__ import annotations
from typing import Dict, Optional, Tuple, List
from .aad import build_canonical_aad, build_canonical_aad_headers_body, canonicalize_core_header_name, build_aad_from_transport
from .errors import (
    NsForbidden,
    AeadUnsupported,
    EcdhLowOrder,
    PublicKeyNotInAad,
    InvalidEnvelope,
    AeadMismatch,
    KidMismatch,
    AadMismatch,
)
from .keys import jwk_to_public_bytes, jwk_to_private_bytes
from .payment import synthesize_payment_header_value
from .extensions import is_approved_extension_header
from nacl import bindings
import base64
import hmac
import hashlib
import json


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64u_to_bytes(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "==")


def _hkdf_sha256(ikm: bytes, info: bytes, length: int) -> bytes:
    salt = bytes(32)  # zeros
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    n = (length + 31) // 32
    t = b""
    okm = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def create_hpke(
    namespace: str,
    kem: str = "X25519",
    kdf: str = "HKDF-SHA256",
    aead: str = "CHACHA20-POLY1305",
    jwks_url: Optional[str] = None,
    public_entities: Optional[object] = None,
):
    if not namespace or namespace.lower() == "x402":
        raise NsForbidden("NS_FORBIDDEN")

    class _HPKE:
        suite = "X25519-HKDF-SHA256-CHACHA20POLY1305"
        version = "v1"
        _default_public = public_entities
        
        def seal(self, *, kid: str, recipient_public_jwk: Dict, transport: object, make_entities_public: Optional[object] = None, __test_eph_seed32: Optional[bytes] = None) -> Tuple[Dict, Optional[Dict]]:
            if aead != "CHACHA20-POLY1305":
                raise AeadUnsupported("AEAD_UNSUPPORTED")

            # Build AAD from transport (verbatim headers/body), private by default
            core = transport.getHeader()
            exts = transport.getExtensions() or []
            body = transport.getBody() or {}
            http_status = transport.getHttpResponseCode()
            headers = ([core] if core else []) + list(exts)
            aad_bytes, headers_norm, body_norm = build_aad_from_transport(namespace, headers, body)

            # Plaintext is the canonicalized body
            plaintext = json.dumps(body_norm).encode("utf-8")

            # HPKE KEM/KDF/AEAD
            eph_skpk = (
                bindings.crypto_kx_seed_keypair(__test_eph_seed32)
                if __test_eph_seed32 is not None
                else bindings.crypto_kx_keypair()
            )
            eph_pub, eph_priv = eph_skpk
            recipient_pub = jwk_to_public_bytes(recipient_public_jwk)
            if recipient_pub == b"\x00" * 32 or all(b == 0 for b in recipient_pub):
                raise EcdhLowOrder("ECDH_LOW_ORDER")
            shared = bindings.crypto_scalarmult(eph_priv, recipient_pub)
            if shared == b"\x00" * 32 or all(b == 0 for b in shared):
                raise EcdhLowOrder("ECDH_LOW_ORDER")
            # HKDF info binds label, suite, namespace, enc, and recipient public key
            info = (
                "x402-hpke:v1|KDF="
                + kdf
                + "|AEAD="
                + aead
                + "|ns="
                + namespace
                + "|enc="
                + _b64u(eph_pub)
                + "|pkR="
                + _b64u(recipient_pub)
            ).encode("utf-8")
            okm = _hkdf_sha256(shared, info, 32 + 12)
            key, nonce = okm[:32], okm[32:]
            ct = bindings.crypto_aead_chacha20poly1305_ietf_encrypt(plaintext, aad_bytes, nonce, key)
            envelope = {
                "typ": "hpke-envelope",
                "ver": "1",
                "ns": namespace,
                "kid": kid,
                "kem": kem,
                "kdf": kdf,
                "aead": aead,
                "enc": _b64u(eph_pub),
                "aad": _b64u(aad_bytes),
                "ct": _b64u(ct),
            }
            # Sidecar generation based on make_entities_public selection
            make_pub = make_entities_public
            if not make_pub:
                return envelope, None

            def _select(keys: List[str]) -> List[str]:
                if isinstance(make_pub, str) and make_pub.lower() in ("all", "*"):
                    return list(keys)
                if isinstance(make_pub, list):
                    s = {str(k).lower() for k in make_pub}
                    return [k for k in keys if k.lower() in s]
                return []

            header_names = [str(h.get("header")) for h in headers_norm]
            if http_status == 402:
                header_names = [h for h in header_names if h.upper() not in ("X-PAYMENT", "X-PAYMENT-RESPONSE")]
            header_sel = _select(header_names)
            body_keys = list((body_norm or {}).keys())
            body_sel = _select(body_keys)
            out: dict = {}
            for hn in header_sel:
                found = next((h for h in headers_norm if str(h.get("header")).lower() == hn.lower()), None)
                if not found:
                    continue
                out[found.get("header")] = synthesize_payment_header_value(found.get("value"))
            for bk in body_sel:
                if bk in body_norm:
                    out[bk] = body_norm[bk]
            return (envelope, out) if out else (envelope, None)

        def open(self, *, recipient_private_jwk: Dict, envelope: Dict, expected_kid: Optional[str] = None, public_headers: Optional[Dict] = None, public_json: Optional[Dict] = None, public_body: Optional[Dict] = None, public_json_body: Optional[Dict] = None):
            if envelope.get("ver") != "1" or envelope.get("ns", "").lower() == "x402":
                raise InvalidEnvelope("INVALID_ENVELOPE")
            if envelope.get("aead") != aead:
                raise AeadMismatch("AEAD_MISMATCH")
            if aead != "CHACHA20-POLY1305":
                raise AeadUnsupported("AEAD_UNSUPPORTED")
            if expected_kid and envelope.get("kid") != expected_kid:
                raise KidMismatch("KID_MISMATCH")
            aad_bytes = _b64u_to_bytes(envelope["aad"])
            sidecar_headers = public_headers or public_json
            sidecar_body = public_body
            sk = jwk_to_private_bytes(recipient_private_jwk)
            eph_pub = _b64u_to_bytes(envelope["enc"]) 
            if eph_pub == b"\x00" * 32 or all(b == 0 for b in eph_pub):
                raise EcdhLowOrder("ECDH_LOW_ORDER")
            shared = bindings.crypto_scalarmult(sk, eph_pub)
            if shared == b"\x00" * 32 or all(b == 0 for b in shared):
                raise EcdhLowOrder("ECDH_LOW_ORDER")
            pkR = bindings.crypto_scalarmult_base(sk)
            info = (
                "x402-hpke:v1|KDF="
                + kdf
                + "|AEAD="
                + aead
                + "|ns="
                + envelope["ns"]
                + "|enc="
                + envelope["enc"]
                + "|pkR="
                + _b64u(pkR)
            ).encode("utf-8")
            okm = _hkdf_sha256(shared, info, 32 + 12)
            key, nonce = okm[:32], okm[32:]
            ct = _b64u_to_bytes(envelope["ct"])
            pt = bindings.crypto_aead_chacha20poly1305_ietf_decrypt(ct, aad_bytes, nonce, key)
            aad_str = _b64u_to_bytes(envelope["aad"]).decode("utf-8")
            segs = aad_str.split("|")
            if len(segs) < 4:
                raise InvalidEnvelope("INVALID_ENVELOPE")
            seg2 = segs[2]
            seg3 = segs[3]
            body = None
            headers = None
            # Try headers/body parse
            try:
                arr = json.loads(seg2)
                if isinstance(arr, list):
                    headers = arr
                    obj = json.loads(seg3) if seg3 else {}
                    if isinstance(obj, dict):
                        body = obj
            except Exception:
                pass
            if headers is not None:
                # Verify sidecars
                if sidecar_headers:
                    for k, v in (sidecar_headers or {}).items():
                        found = next((h for h in headers if str(h.get("header", "")).lower() == str(k).lower()), None)
                        if not found:
                            raise PublicKeyNotInAad("PUBLIC_KEY_NOT_IN_AAD")
                        expect = synthesize_payment_header_value(found.get("value", {}))
                        if str(v or "").strip() != expect:
                            raise AadMismatch("AAD_MISMATCH")
                if sidecar_body and body:
                    for k, v in (sidecar_body or {}).items():
                        if k not in body:
                            raise PublicKeyNotInAad("PUBLIC_KEY_NOT_IN_AAD")
                        expect = json.dumps(body.get(k), separators=(",", ":"))
                        got = json.dumps(v, separators=(",", ":"))
                        if expect != got:
                            raise AadMismatch("AAD_MISMATCH")
                return pt, body, headers
            # Legacy parse
            x402 = json.loads(seg2)
            app = json.loads(seg3) if seg3 else None
            if sidecar_headers is not None:
                def _find(hname: str) -> Optional[str]:
                    for k, v in (sidecar_headers or {}).items():
                        if isinstance(k, str) and k.lower() == hname.lower():
                            return v.strip() if isinstance(v, str) else v
                    return None
                xp = _find("X-PAYMENT")
                xpr = _find("X-PAYMENT-RESPONSE")
                if xp and x402.get("header") == "X-Payment":
                    expect = synthesize_payment_header_value(x402.get("payload", {}))
                    if xp != expect:
                        raise AadMismatch("AAD_MISMATCH")
                if xpr and x402.get("header") == "X-Payment-Response":
                    expect = synthesize_payment_header_value(x402.get("payload", {}))
                    if xpr != expect:
                        raise AadMismatch("AAD_MISMATCH")
                for k, v in (sidecar_headers or {}).items():
                    if not isinstance(k, str) or not is_approved_extension_header(k):
                        continue
                    ext_list = (app or {}).get("extensions") or []
                    found = None
                    for e in ext_list:
                        if str(e.get("header", "")).lower() == k.lower():
                            found = e
                            break
                    if not found:
                        raise PublicKeyNotInAad("PUBLIC_KEY_NOT_IN_AAD")
                    expect = synthesize_payment_header_value(found.get("payload", {}))
                    if (v or "").strip() != expect:
                        raise AadMismatch("AAD_MISMATCH")
            return pt, x402, app

    return _HPKE()