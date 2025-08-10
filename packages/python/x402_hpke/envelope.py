from __future__ import annotations
from typing import Dict, Optional, Tuple, List
from .aad import build_canonical_aad, build_canonical_aad_headers_body, canonicalize_core_header_name
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
        
        def seal(self, *, kid: str, recipient_public_jwk: Dict, private_headers: Optional[List[Dict]] = None, private_body: Optional[Dict] = None, request: Optional[Dict] = None, response: Optional[Dict] = None, x402: Optional[Dict] = None, extensions: Optional[list] = None, public: Optional[Dict] = None, http_response_code: Optional[int] = None, plaintext: Optional[bytes] = None, __test_eph_seed32: Optional[bytes] = None) -> Tuple[Dict, Optional[Dict]]:
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
            
            # New canonical path if headers/body provided
            use_headers_body = (private_headers is not None and isinstance(private_headers, list)) or (private_body is not None)
            if use_headers_body:
                hdrs = list(private_headers or [])
                body = dict(private_body or {})
                # collision check
                lower_names = {str((h or {}).get("header", "")).lower() for h in hdrs}
                for k in body.keys():
                    if k.lower() in lower_names:
                        raise InvalidEnvelope("BODY_HEADER_NAME_COLLISION")
                # core headers rules
                core = [
                    (i, canonicalize_core_header_name(str((h or {}).get("header", ""))), h)
                    for i, h in enumerate(hdrs)
                ]
                core = [x for x in core if x[1] in ("X-Payment", "X-Payment-Response", "")]
                kinds = {x[1] for x in core}
                if len(kinds) > 1:
                    raise InvalidEnvelope("MULTIPLE_CORE_X402_HEADERS")
                if len(core) > 1:
                    raise InvalidEnvelope("DUPLICATE_CORE_X402_HEADER")
                if core:
                    i, name, entry = core[0]
                    if name == "X-Payment":
                        if http_response_code is not None:
                            raise InvalidEnvelope("X_PAYMENT_STATUS")
                        val = (entry or {}).get("value")
                        if not isinstance(val, dict) or "payload" not in val:
                            raise InvalidEnvelope("X_PAYMENT_PAYLOAD")
                    elif name == "X-Payment-Response":
                        if http_response_code is None:
                            http_response_code = 200
                        if http_response_code != 200:
                            raise InvalidEnvelope("X_PAYMENT_RESPONSE_STATUS")
                    else:  # ""
                        if http_response_code is None:
                            http_response_code = 402
                        if http_response_code != 402:
                            raise InvalidEnvelope("INVALID_402_HEADER_STATUS")
                        val = (entry or {}).get("value") or {}
                        if not private_body:
                            body = dict(val) if isinstance(val, dict) else {}
                        # remove empty header
                        del hdrs[i]
                aad_bytes, headers_norm, body_norm = build_canonical_aad_headers_body(namespace, hdrs, body)
                if plaintext is None:
                    plaintext = json.dumps(body_norm).encode("utf-8")
            else:
                # Legacy path
                if request is None and response is None and x402 is None:
                    raise ValueError("One of 'request', 'response', or 'x402' must be provided.")
                if request is not None and http_response_code is not None:
                    raise ValueError("'http_response_code' is not allowed for 'request' payloads.")
                if response is not None and http_response_code is None:
                    raise ValueError("'http_response_code' is required for 'response' payloads.")
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
                if plaintext is None:
                    if request:
                        plaintext = json.dumps(request).encode("utf-8")
                    elif response:
                        plaintext = json.dumps(response).encode("utf-8")
                    elif x402:
                        if http_response_code == 402 and x402.get("header") == "":
                            plaintext = json.dumps(x402.get("payload", {})).encode("utf-8")
                        else:
                            plaintext = json.dumps(x402).encode("utf-8")
                aad_bytes, xnorm, request_norm, response_norm, ext_norm = build_canonical_aad(namespace, {"request": request, "response": response, "x402": x402}, extensions)
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
            app = {"extensions": ext_norm} if ext_norm else None
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
            
            # If using headers/body model, project from that
            if use_headers_body:
                make_pub_in = (public or {}).get("makeEntitiesPublic")
                make_priv_in = (public or {}).get("makeEntitiesPrivate") or []
                def _select(keys: List[str]) -> List[str]:
                    if make_pub_in in ("all", "*"):
                        sel = list(keys)
                    elif isinstance(make_pub_in, list):
                        up = {str(k).lower() for k in make_pub_in}
                        sel = [k for k in keys if k.lower() in up]
                    else:
                        sel = []
                    priv = {str(k).lower() for k in make_priv_in} if isinstance(make_priv_in, list) else set()
                    return [k for k in sel if k.lower() not in priv]
                # Collect normalized sets used above
                # rebuild to ensure names
                _, headers_norm, body_norm = build_canonical_aad_headers_body(namespace, hdrs, body)
                header_names = [h.get("header") for h in headers_norm]
                # 402 rule: drop core headers
                if http_response_code == 402:
                    header_names = [h for h in header_names if canonicalize_core_header_name(h) not in ("X-Payment", "X-Payment-Response")]
                header_sel = _select(header_names)
                body_keys = list((body_norm or {}).keys())
                body_sel = _select(body_keys)
                if as_kind == "headers":
                    # For generic request/response, expose a JSON body rather than headers
                    if body_sel:
                        out_body = {k: body_norm[k] for k in body_sel if k in body_norm}
                        return envelope, out_body if out_body else None
                    out = {}
                    for hn in header_sel:
                        found = next((h for h in headers_norm if str(h.get("header")).lower() == hn.lower()), None)
                        if not found:
                            continue
                        canon = canonicalize_core_header_name(found.get("header"))
                        key = "X-PAYMENT" if canon == "X-Payment" else "X-PAYMENT-RESPONSE" if canon == "X-Payment-Response" else found.get("header")
                        out[key] = synthesize_payment_header_value(found.get("value"))
                    return envelope, out if out else None
                else:
                    out_headers = {}
                    for hn in header_sel:
                        found = next((h for h in headers_norm if str(h.get("header")).lower() == hn.lower()), None)
                        if not found:
                            continue
                        canon = canonicalize_core_header_name(found.get("header"))
                        key = "X-PAYMENT" if canon == "X-Payment" else "X-PAYMENT-RESPONSE" if canon == "X-Payment-Response" else found.get("header")
                        out_headers[key] = synthesize_payment_header_value(found.get("value"))
                    out_body = {k: body_norm[k] for k in body_sel if k in body_norm}
                    return envelope, out_headers if out_headers or out_body else None

            # Legacy sidecar path
            # For 402 responses, never send X-402 headers in sidecar
            if http_response_code == 402:
                # Only emit approved extensions if explicitly requested
                make_pub_in = (public or {}).get("makeEntitiesPublic")
                ext_allow = []
                if isinstance(make_pub_in, str) and make_pub_in.lower() in ("all", "*"):
                    if ext_norm and isinstance(ext_norm, list):
                        ext_allow = [str(e.get("header", "")) for e in ext_norm if is_approved_extension_header(str(e.get("header", "")))]
                elif isinstance(make_pub_in, list):
                    # For 402, only process approved extension headers, ignore core payment headers
                    ext_allow = [h for h in make_pub_in if is_approved_extension_header(h)]
                
                # Apply makeEntitiesPrivate filter
                make_priv = (public or {}).get("makeEntitiesPrivate")
                if isinstance(make_priv, list):
                    priv_set = {str(s).upper() for s in make_priv}
                    ext_allow = [h for h in ext_allow if str(h).upper() not in priv_set]
                
                # 402 responses only emit extensions, never core payment headers
                if not ext_allow:
                    return envelope, None
                
                if as_kind == "headers":
                    headers = {}
                    if ext_allow and ext_norm and isinstance(ext_norm, list):
                        for wanted in ext_allow:
                            if not self._is_approved_extension_header(wanted):
                                continue
                            found = next((e for e in ext_norm if str(e.get("header", "")).lower() == wanted.lower()), None)
                            if not found:
                                raise PublicKeyNotInAad("PUBLIC_KEY_NOT_IN_AAD")
                            headers[found["header"]] = self._synthesize_payment_header_value(found["payload"])
                    return envelope, headers
                else:
                    json_data = {}
                    if ext_allow and ext_norm and isinstance(ext_norm, list):
                        for wanted in ext_allow:
                            if not self._is_approved_extension_header(wanted):
                                continue
                            found = next((e for e in ext_norm if str(e.get("header", "")).lower() == wanted.lower()), None)
                            if not found:
                                raise PublicKeyNotInAad("PUBLIC_KEY_NOT_IN_AAD")
                            json_data[found["header"]] = self._synthesize_payment_header_value(found["payload"])
                    return envelope, json_data

            # For non-402 responses and client requests, can emit both payment headers and extensions
            if as_kind == "headers":
                headers = {}
                
                # Emit x402 headers if requested and available
                if x402 and (public or {}).get("makeEntitiesPublic"):
                    make_pub = (public or {}).get("makeEntitiesPublic")
                    wants_all = isinstance(make_pub, str) and make_pub.lower() in ("all", "*")
                    wants = {str(s).upper() for s in (make_pub or [])} if isinstance(make_pub, list) else set()
                    if wants_all or "X-PAYMENT" in wants or "X-PAYMENT-RESPONSE" in wants:
                        if x402.get("header") == "X-Payment":
                            headers["X-PAYMENT"] = synthesize_payment_header_value(x402["payload"])
                        elif x402.get("header") == "X-Payment-Response":
                            headers["X-PAYMENT-RESPONSE"] = synthesize_payment_header_value(x402["payload"])
                
                # Emit extension headers if requested and available
                if ext_norm and isinstance(ext_norm, list) and (public or {}).get("makeEntitiesPublic"):
                    make_pub = (public or {}).get("makeEntitiesPublic")
                    ext_allow = []
                    if isinstance(make_pub, str) and make_pub.lower() in ("all", "*"):
                        ext_allow = [str(e.get("header", "")) for e in ext_norm if self._is_approved_extension_header(str(e.get("header", "")))]
                    elif isinstance(make_pub, list):
                        ext_allow = [h for h in make_pub if self._is_approved_extension_header(h)]
                    
                    # Apply makeEntitiesPrivate filter
                    make_priv = (public or {}).get("makeEntitiesPrivate")
                    if isinstance(make_priv, list):
                        priv_set = {str(s).upper() for s in make_priv}
                        ext_allow = [h for h in ext_allow if str(h).upper() not in priv_set]
                    
                    for wanted in ext_allow:
                        if not self._is_approved_extension_header(wanted):
                            continue
                        found = next((e for e in ext_norm if str(e.get("header", "")).lower() == wanted.lower()), None)
                        if not found:
                            raise PublicKeyNotInAad("PUBLIC_KEY_NOT_IN_AAD")
                        headers[found["header"]] = self._synthesize_payment_header_value(found["payload"])
                
                if headers:
                    return envelope, headers
            else:
                json_data = {}
                
                # Emit x402 headers if requested and available
                if x402 and (public or {}).get("makeEntitiesPublic"):
                    make_pub = (public or {}).get("makeEntitiesPublic")
                    wants_all = isinstance(make_pub, str) and make_pub.lower() in ("all", "*")
                    wants = {str(s).upper() for s in (make_pub or [])} if isinstance(make_pub, list) else set()
                    if wants_all or "X-PAYMENT" in wants or "X-PAYMENT-RESPONSE" in wants:
                        if x402.get("header") == "X-Payment":
                            json_data["X-PAYMENT"] = synthesize_payment_header_value(x402["payload"])
                        elif x402.get("header") == "X-Payment-Response":
                            json_data["X-PAYMENT-RESPONSE"] = synthesize_payment_header_value(x402["payload"])
                
                # Emit extension headers if requested and available
                if ext_norm and isinstance(ext_norm, list) and (public or {}).get("makeEntitiesPublic"):
                    make_pub = (public or {}).get("makeEntitiesPublic")
                    ext_allow = []
                    if isinstance(make_pub, str) and make_pub.lower() in ("all", "*"):
                        ext_allow = [str(e.get("header", "")) for e in ext_norm if self._is_approved_extension_header(str(e.get("header", "")))]
                    elif isinstance(make_pub, list):
                        ext_allow = [h for h in make_pub if self._is_approved_extension_header(h)]
                    
                    # Apply makeEntitiesPrivate filter
                    make_priv = (public or {}).get("makeEntitiesPrivate")
                    if isinstance(make_priv, list):
                        priv_set = {str(s).upper() for s in make_priv}
                        ext_allow = [h for h in ext_allow if str(h).upper() not in priv_set]
                    
                    for wanted in ext_allow:
                        if not self._is_approved_extension_header(wanted):
                            continue
                        found = next((e for e in ext_norm if str(e.get("header", "")).lower() == wanted.lower()), None)
                        if not found:
                            raise PublicKeyNotInAad("PUBLIC_KEY_NOT_IN_AAD")
                        json_data[found["header"]] = self._synthesize_payment_header_value(found["payload"])
                
                if json_data:
                    return envelope, json_data
            
            return envelope, None

        def open(self, *, recipient_private_jwk: Dict, envelope: Dict, expected_kid: Optional[str] = None, public_headers: Optional[Dict] = None, public_json: Optional[Dict] = None, public_body: Optional[Dict] = None, public_json_body: Optional[Dict] = None) -> Tuple[bytes, Optional[Dict], Optional[Dict], Optional[Dict], Optional[list]]:
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