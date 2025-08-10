from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional
from warnings import warn

from .constants import CanonicalHeaders


class TransportType(Enum):
    PAYMENT = "PAYMENT"
    PAYMENT_RESPONSE = "PAYMENT_RESPONSE"
    PAYMENT_REQUIRED = "PAYMENT_REQUIRED"
    OTHER_REQUEST = "OTHER_REQUEST"
    OTHER_RESPONSE = "OTHER_RESPONSE"


def _is_object(value: Any) -> bool:
    return isinstance(value, dict)


def _is_non_empty_object(value: Any) -> bool:
    return _is_object(value) and len(value) > 0


@dataclass
class x402SecureTransport:
    _headerCore: Optional[Dict[str, Any]] = None
    _body: Dict[str, Any] = None  # type: ignore[assignment]
    _httpResponseCode: Optional[int] = None
    _extensions: List[Dict[str, Any]] = None  # type: ignore[assignment]

    def __init__(
        self,
        type: TransportType,
        content: Optional[Dict[str, Any]] = None,
        http_response_code: Optional[int] = None,
        extensions: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        if content is None:
            content = {}
        if not _is_object(content):
            raise Exception("CONTENT_OBJECT")
        self._extensions = list(extensions) if isinstance(extensions, list) else []

        if type == TransportType.OTHER_REQUEST:
            if http_response_code is not None:
                raise Exception("OTHER_REQUEST_HTTP_CODE")
            self._body = content
        elif type == TransportType.OTHER_RESPONSE:
            if http_response_code == 402:
                raise Exception("OTHER_RESPONSE_402")
            self._httpResponseCode = http_response_code
            self._body = content
        elif type == TransportType.PAYMENT_REQUIRED:
            if not _is_non_empty_object(content):
                raise Exception("PAYMENT_REQUIRED_CONTENT")
            if http_response_code is not None and http_response_code != 402:
                warn("PAYMENT_REQUIRED_HTTP_CODE_WARN: Coercing to 402")
            self._httpResponseCode = 402
            self._body = content
        elif type == TransportType.PAYMENT_RESPONSE:
            if not _is_non_empty_object(content):
                raise Exception("PAYMENT_RESPONSE_CONTENT")
            if http_response_code is not None and http_response_code != 200:
                raise Exception("PAYMENT_RESPONSE_HTTP_CODE")
            self._httpResponseCode = 200
            self._headerCore = {"header": CanonicalHeaders["X_PAYMENT_RESPONSE"], "value": content}
            self._body = {}
        elif type == TransportType.PAYMENT:
            if http_response_code is not None:
                raise Exception("PAYMENT_HTTP_CODE")
            if "payload" not in content:
                raise Exception("PAYMENT_PAYLOAD")
            self._headerCore = {"header": CanonicalHeaders["X_PAYMENT"], "value": content}
            self._body = {}
        else:
            raise Exception("UNSUPPORTED_TYPE")

    def getHeader(self) -> Optional[Dict[str, Any]]:
        return self._headerCore

    def getBody(self) -> Dict[str, Any]:
        return self._body

    def getExtensions(self) -> List[Dict[str, Any]]:
        return self._extensions

    def getHttpResponseCode(self) -> Optional[int]:
        return self._httpResponseCode


