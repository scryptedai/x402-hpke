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
from .headers import build_x402_headers
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


def create_hpke(namespace: str, kem: str = "X25519", kdf: str = "HKDF-SHA256", aead: str = "CHACHA20-POLY1305", jwks_url: Optional[str] = None):
    if not namespace or namespace.lower() == "x402":
        raise NsForbidden("NS_FORBIDDEN")

    class _HPKE:
        suite = "X25519-HKDF-SHA256-CHACHA20POLY1305"
        version = "v1"
        def seal(self, *, kid: str, recipient_public_jwk: Dict, plaintext: bytes, x402: Dict, app: Optional[Dict] = None, public: Optional[Dict] = None, __test_eph_seed32: Optional[bytes] = None) -> Tuple[Dict, Optional[Dict]]:
            if aead != "CHACHA20-POLY1305":
                raise AeadUnsupported("AEAD_UNSUPPORTED")
            # Preflight: forbid exposing reply-to metadata or replyPublicOk via sidecar allowlist
            app_allow = (public or {}).get("appHeaderAllowlist", []) or []
            for k in app_allow:
                kl = str(k).lower()
                if kl.startswith("replyto") or kl == "replypublicok":
                    raise PublicKeyNotInAad("REPLY_TO_SIDECAR_FORBIDDEN")
            aad_bytes, xnorm, _ = build_canonical_aad(namespace, x402, app)
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
            as_kind = (public or {}).get("as", "headers")
            want_x402 = bool((public or {}).get("x402Headers", False))
            app_allow = (public or {}).get("appHeaderAllowlist", []) or []
            if not want_x402 and len(app_allow) == 0:
                return envelope, None
            if as_kind == "headers":
                hdrs: Dict[str, str] = {}
                if want_x402:
                    hdrs.update(build_x402_headers(xnorm))
                if app_allow and app:
                    for k in app_allow:
                        if k not in app:
                            raise PublicKeyNotInAad("PUBLIC_KEY_NOT_IN_AAD")
                        kl = k.lower()
                        if kl.startswith("replyto") or kl == "replypublicok":
                            raise PublicKeyNotInAad("REPLY_TO_SIDECAR_FORBIDDEN")
                        hdrs[f"X-{namespace}-{k}"] = str(app[k])
                return envelope, hdrs
            else:
                j: Dict[str, str] = {}
                if want_x402:
                    j.update(build_x402_headers(xnorm))
                if app_allow and app:
                    for k in app_allow:
                        if k not in app:
                            raise PublicKeyNotInAad("PUBLIC_KEY_NOT_IN_AAD")
                        kl = k.lower()
                        if kl.startswith("replyto") or kl == "replypublicok":
                            raise PublicKeyNotInAad("REPLY_TO_SIDECAR_FORBIDDEN")
                        j[f"X-{namespace}-{k}"] = str(app[k])
                return envelope, j

        def open(self, *, recipient_private_jwk: Dict, envelope: Dict, expected_kid: Optional[str] = None, public_headers: Optional[Dict] = None, public_json: Optional[Dict] = None) -> Tuple[bytes, Dict, Optional[Dict]]:
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
            if sidecar is not None:
                def _get(hname: str) -> str | None:
                    for k, v in sidecar.items():
                        if isinstance(k, str) and k.lower() == hname.lower():
                            return v.strip() if isinstance(v, str) else v
                    return None
                hx = {
                    "invoiceId": _get("X-X402-Invoice-Id"),
                    "chainId": int(_get("X-X402-Chain-Id")),
                    "tokenContract": _get("X-X402-Token-Contract"),
                    "amount": _get("X-X402-Amount"),
                    "recipient": _get("X-X402-Recipient"),
                    "txHash": _get("X-X402-Tx-Hash"),
                    "expiry": int(_get("X-X402-Expiry")),
                    "priceHash": _get("X-X402-Price-Hash"),
                }
                rebuilt, _, _ = build_canonical_aad(envelope["ns"], hx)
                if not hmac.compare_digest(rebuilt, aad_bytes):
                    raise AadMismatch("AAD_MISMATCH")
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
            return pt, x402, app

    return _HPKE()