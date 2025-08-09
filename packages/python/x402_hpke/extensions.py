from __future__ import annotations
from typing import Dict, Any, List, TypedDict


APPROVED_EXTENSION_HEADERS: List[str] = [
    "X-402-Routing",
    "X-402-Limits",
    "X-402-Acceptable",
    "X-402-Metadata",
]


class X402Extension(TypedDict, total=False):
    header: str
    payload: Dict[str, Any]
    # Additional keys allowed


def is_approved_extension_header(header: str) -> bool:
    return any(h.lower() == str(header).lower() for h in APPROVED_EXTENSION_HEADERS)


def canonicalize_extension_header(header: str) -> str:
    for h in APPROVED_EXTENSION_HEADERS:
        if h.lower() == str(header).lower():
            return h
    raise ValueError("X402_EXTENSION_UNAPPROVED")

