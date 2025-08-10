from typing import Dict, Any, Tuple, Optional
from .envelope import create_hpke

def create_payment_required(
    hpke: object,
    payment_required_data: Dict[str, Any],
    recipient_public_jwk: Dict[str, Any],
    plaintext: bytes,
    kid: str,
    is_public: bool = False,
) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    """
    A helper to create a 402 Payment Required response.
    """
    return hpke.seal(
        response=payment_required_data,
        http_response_code=402,
        public={"makeEntitiesPublic": ["response"]} if is_public else None,
        recipient_public_jwk=recipient_public_jwk,
        plaintext=plaintext,
        kid=kid,
    )