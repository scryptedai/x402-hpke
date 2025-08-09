from typing import Dict, Tuple
from .errors import (
    InvalidEnvelope,
    JwksHttpsRequired,
    JwksHttpError,
    JwksInvalid,
    JwksKeyInvalid,
    JwksKeyUseInvalid,
    JwksKidInvalid,
    JwksEmpty,
    KidNotFound,
)
from nacl import bindings
import base64
import time
import requests

_jwks_cache: dict[str, tuple[dict, float]] = {}


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def generate_keypair() -> Tuple[Dict, Dict]:
    sk = bindings.crypto_kx_keypair()
    pub = sk[0]
    priv = sk[1]
    public_jwk = {"kty": "OKP", "crv": "X25519", "x": _b64u(pub)}
    private_jwk = {**public_jwk, "d": _b64u(priv)}
    return public_jwk, private_jwk


def generate_public_jwk() -> Dict:
    """Return a freshly generated public JWK (OKP X25519)."""
    pub, _ = generate_keypair()
    return pub


def jwk_to_public_bytes(jwk: Dict) -> bytes:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "X25519" or "x" not in jwk:
        raise InvalidEnvelope("INVALID_ENVELOPE")
    x = jwk["x"].encode("ascii")
    return base64.urlsafe_b64decode(x + b"==")


def jwk_to_private_bytes(jwk: Dict) -> bytes:
    if "d" not in jwk:
        raise InvalidEnvelope("INVALID_ENVELOPE")
    d = jwk["d"].encode("ascii")
    return base64.urlsafe_b64decode(d + b"==")


def _parse_cache_headers(headers: dict) -> int | None:
    cc = headers.get("Cache-Control") or headers.get("cache-control") or ""
    if cc:
        for part in cc.split(","):
            part = part.strip().lower()
            if part.startswith("s-maxage=") or part.startswith("max-age="):
                try:
                    return int(part.split("=")[1])
                except Exception:
                    pass
    exp = headers.get("Expires") or headers.get("expires")
    if exp:
        try:
            from email.utils import parsedate_to_datetime
            return max(0, int(parsedate_to_datetime(exp).timestamp() - time.time()))
        except Exception:
            return None
    return None


def fetch_jwks(url: str, min_ttl: int = 60, max_ttl: int = 3600) -> dict:
    if not url.startswith("https://"):
        raise JwksHttpsRequired("JWKS_HTTPS_REQUIRED")
    now = time.time()
    cached = _jwks_cache.get(url)
    if cached and cached[1] > now:
        return cached[0]
    r = requests.get(url, timeout=5)
    if r.status_code != 200:
        raise JwksHttpError(f"JWKS_HTTP_{r.status_code}")
    jwks = r.json()
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise JwksInvalid("JWKS_INVALID")
    for k in jwks["keys"]:
        if k.get("kty") != "OKP" or k.get("crv") != "X25519" or not isinstance(k.get("x"), str):
            raise JwksKeyInvalid("JWKS_KEY_INVALID")
        if k.get("use") and k.get("use") != "enc":
            raise JwksKeyUseInvalid("JWKS_KEY_USE_INVALID")
        if not isinstance(k.get("kid"), str):
            raise JwksKidInvalid("JWKS_KID_INVALID")
    ttl = _parse_cache_headers(r.headers) or 300
    ttl = max(min_ttl, min(ttl, max_ttl))
    _jwks_cache[url] = (jwks, now + ttl)
    return jwks


def set_jwks(url: str, jwks: dict, ttl: int = 300) -> None:
    _jwks_cache[url] = (jwks, time.time() + ttl)


def select_jwk(kid: str, jwks: dict | None = None, url: str | None = None) -> dict:
    set_ = jwks
    if set_ is None and url is not None:
        cached = _jwks_cache.get(url)
        if cached:
            set_ = cached[0]
    if not set_:
        raise JwksEmpty("JWKS_EMPTY")
    for k in set_["keys"]:
        if isinstance(k.get("kid"), str) and k["kid"] == kid:
            return k
    raise KidNotFound("KID_NOT_FOUND")