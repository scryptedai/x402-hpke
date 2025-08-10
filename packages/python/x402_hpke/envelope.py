from __future__ import annotations
from typing import Dict, Optional, Tuple
from .aad import build_canonical_aad
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
        
        def seal(self, *, kid: str, recipient_public_jwk: Dict, plaintext: bytes, request: Optional[Dict] = None, response: Optional[Dict] = None, x402: Optional[Dict] = None, extensions: Optional[list] = None, public: Optional[Dict] = None, http_response_code: Optional[int] = None, __test_eph_seed32: Optional[bytes] = None) -> Tuple[Dict, Optional[Dict]]:
            # Rule 1: Mutually Exclusive Payloads
            payload_count = sum(p is not None for p in [request, response, x402])
            if payload_count > 1:
                raise ValueError("Only one of 'request', 'response', or 'x402' can be provided.")
            if payload_count == 0:
                raise ValueError("One of 'request', 'response', or 'x402' must be provided.")

            # Rule 2: The `request` Object
            if request is not None:
                if http_response_code is not None:
                    raise ValueError("'http_response_code' is not allowed for 'request' payloads.")

            # Rule 3: The `response` Object
            if response is not None:
                if http_response_code is None:
                    raise ValueError("'http_response_code' is required for 'response' payloads.")

            # Rule 4: The `x402` Object
            if x402 is not None:
                if http_response_code == 200 and x402.get("header") != "X-Payment-Response":
                    raise ValueError("For http_response_code 200, x402.header must be 'X-Payment-Response'.")
                if http_response_code == 402 and x402.get("header") != "":
                    raise ValueError("For http_response_code 402, x402.header must be an empty string.")
                if http_response_code is None:
                    if x402.get("header") == "X-Payment-Response":
                        http_response_code = 200
                    elif x402.get("header") == "":
                        http_response_code = 402
            
            if aead != "CHACHA20-POLY1305":
                raise AeadUnsupported("AEAD_UNSUPPORTED")
            
            aad_bytes, xnorm, _, _, _ = build_canonical_aad(namespace, {"request": request, "response": response, "x402": x402}, extensions)
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
            # Inject constructor defaults for public entities if not provided
            if public is None:
                public = {}
            if self._default_public is not None and public.get("makeEntitiesPublic") is None:
                public["makeEntitiesPublic"] = self._default_public
            as_kind = (public or {}).get("as", "headers")
            
            # Sidecar Generation
            make_pub = (public or {}).get("makeEntitiesPublic")
            if make_pub:
                if (isinstance(make_pub, str) and make_pub.lower() in ("all", "*") or (isinstance(make_pub, list) and "request" in make_pub)) and request:
                    return envelope, request
                if (isinstance(make_pub, str) and make_pub.lower() in ("all", "*") or (isinstance(make_pub, list) and "response" in make_pub)) and response:
                    return envelope, response

            # Three use cases for sidecar generation:
            # 1. Client request (no http_response_code): Can include X-PAYMENT in sidecar
            # 2. 402 response: No X-402 headers sent (but body is encrypted)
            # 3. Success response (200+): Can include X-PAYMENT-RESPONSE in sidecar
            
            # For 402 responses, never send X-402 headers in sidecar
            if http_response_code == 402:
                # Only emit approved extensions if explicitly requested
                make_pub_in = (public or {}).get("makeEntitiesPublic")
                ext_allow: list[str] = []
                if isinstance(make_pub_in, str) and make_pub_in.lower() in ("all", "*"):
                    if app and isinstance(app.get("extensions"), list):
                        ext_allow = [str(e.get("header")) for e in app["extensions"] if is_approved_extension_header(str(e.get("header")))]
                elif isinstance(make_pub_in, list):
                    # For 402, only process approved extension headers, ignore core payment headers
                    ext_allow = [x for x in make_pub_in if is_approved_extension_header(x)]
                
                # Apply makeEntitiesPrivate filter
                make_priv = (public or {}).get("makeEntitiesPrivate")
                if isinstance(make_priv, list) and len(ext_allow) > 0:
                    privset = set(x.upper() for x in make_priv)
                    ext_allow = [h for h in ext_allow if h.upper() not in privset]
                
                # 402 responses only emit extensions, never core payment headers
                if len(ext_allow) == 0:
                    return envelope, None
                
                if as_kind == "headers":
                    hdrs: Dict[str, str] = {}
                    if ext_allow and app and isinstance(app.get("extensions"), list):
                        for wanted in ext_allow:
                            if not is_approved_extension_header(wanted):
                                continue
                            found = next((e for e in app["extensions"] if str(e.get("header", "")).lower() == str(wanted).lower()), None)
                            if not found:
                                raise PublicKeyNotInAad("PUBLIC_KEY_NOT_IN_AAD")
                            hdrs[found["header"]] = synthesize_payment_header_value(found.get("payload", {}))
                    return envelope, hdrs
                else:
                    j: Dict[str, str] = {}
                    if ext_allow and app and isinstance(app.get("extensions"), list):
                        for wanted in ext_allow:
                            if not is_approved_extension_header(wanted):
                                continue
                            found = next((e for e in app["extensions"] if str(e.get("header", "")).lower() == str(wanted).lower()), None)
                            if not found:
                                raise PublicKeyNotInAad("PUBLIC_KEY_NOT_IN_AAD")
                            j[found["header"]] = synthesize_payment_header_value(found.get("payload", {}))
                    return envelope, j
            
            # For non-402 responses (including client requests), handle normal sidecar logic
            # Determine entities to emit via makeEntitiesPublic
            make_pub_in = (public or {}).get("makeEntitiesPublic")
            reveal_payment = False
            ext_allow: list[str] = []
            if isinstance(make_pub_in, str) and make_pub_in.lower() in ("all", "*"):
                reveal_payment = True
                if app and isinstance(app.get("extensions"), list):
                    ext_allow = [str(e.get("header")) for e in app["extensions"] if is_approved_extension_header(str(e.get("header")))]
            elif isinstance(make_pub_in, list):
                lst = [str(x) for x in make_pub_in]
                reveal_payment = any(x.upper() in ("X-PAYMENT", "X-PAYMENT-RESPONSE") for x in lst)
                ext_allow = [x for x in lst if is_approved_extension_header(x)]
            # Apply makeEntitiesPrivate subtraction
            make_priv = (public or {}).get("makeEntitiesPrivate")
            if isinstance(make_priv, list) and len(ext_allow) > 0:
                privset = set(x.upper() for x in make_priv)
                ext_allow = [h for h in ext_allow if h.upper() not in privset]
                if reveal_payment:
                    if "X-PAYMENT" in privset and str(xnorm.get("header")) == "X-Payment":
                        reveal_payment = False
                    if "X-PAYMENT-RESPONSE" in privset and str(xnorm.get("header")) == "X-Payment-Response":
                        reveal_payment = False
            if not reveal_payment and len(ext_allow) == 0:
                return envelope, None
            if as_kind == "headers":
                hdrs: Dict[str, str] = {}
                if reveal_payment:
                    h = "X-PAYMENT" if str(xnorm.get("header", "")).lower() == "x-payment" else "X-PAYMENT-RESPONSE"
                    hdrs[h] = synthesize_payment_header_value(xnorm.get("payload", {}))
                if ext_allow and app and isinstance(app.get("extensions"), list):
                    for wanted in ext_allow:
                        if not is_approved_extension_header(wanted):
                            continue
                        found = next((e for e in app["extensions"] if str(e.get("header", "")).lower() == str(wanted).lower()), None)
                        if not found:
                            raise PublicKeyNotInAad("PUBLIC_KEY_NOT_IN_AAD")
                        hdrs[found["header"]] = synthesize_payment_header_value(found.get("payload", {}))
                return envelope, hdrs
            else:
                j: Dict[str, str] = {}
                if reveal_payment:
                    h = "X-PAYMENT" if str(xnorm.get("header", "")).lower() == "x-payment" else "X-PAYMENT-RESPONSE"
                    j[h] = synthesize_payment_header_value(xnorm.get("payload", {}))
                if ext_allow and app and isinstance(app.get("extensions"), list):
                    for wanted in ext_allow:
                        if not is_approved_extension_header(wanted):
                            continue
                        found = next((e for e in app["extensions"] if str(e.get("header", "")).lower() == str(wanted).lower()), None)
                        if not found:
                            raise PublicKeyNotInAad("PUBLIC_KEY_NOT_IN_AAD")
                        j[found["header"]] = synthesize_payment_header_value(found.get("payload", {}))
                return envelope, j

        def open(self, *, recipient_private_jwk: Dict, envelope: Dict, expected_kid: Optional[str] = None, public_headers: Optional[Dict] = None, public_json: Optional[Dict] = None, public_json_body: Optional[Dict] = None) -> Tuple[bytes, Optional[Dict], Optional[Dict], Optional[Dict], Optional[list]]:
            if envelope.get("ver") != "1" or envelope.get("ns", "").lower() == "x402":
                raise InvalidEnvelope("INVALID_ENVELOPE")
            if envelope.get("aead") != aead:
                raise AeadMismatch("AEAD_MISMATCH")
            if aead != "CHACHA20-POLY1305":
                raise AeadUnsupported("AEAD_UNSUPPORTED")
            if expected_kid and envelope.get("kid") != expected_kid:
                raise KidMismatch("KID_MISMATCH")
            aad_bytes = _b64u_to_bytes(envelope["aad"]) 
            sidecar = public_headers or public_json
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
            x402 = json.loads(segs[2])
            app = json.loads(segs[3]) if segs[3] else None
            # Verify sidecar payment/extension headers
            if sidecar is not None:
                def _find(hname: str) -> Optional[str]:
                    for k, v in sidecar.items():
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
                # extensions
                for k, v in (sidecar or {}).items():
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