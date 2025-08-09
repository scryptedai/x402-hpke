from __future__ import annotations
from typing import Optional
from nacl import bindings


def _le64(n: int) -> bytes:
    if n < 0:
        raise ValueError("SEQ_NEGATIVE")
    b = bytearray(8)
    x = n
    for i in range(8):
        b[i] = x & 0xFF
        x >>= 8
    return bytes(b)


def seal_chunk_xchacha(key: bytes, nonce_prefix16: bytes, seq: int, chunk: bytes, aad: Optional[bytes] = None) -> bytes:
    if len(key) != 32:
        raise ValueError("STREAM_KEY_LEN")
    if len(nonce_prefix16) != 16:
        raise ValueError("STREAM_NONCE_PREFIX_LEN")
    nonce = nonce_prefix16 + _le64(seq)
    return bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(chunk, aad, nonce, key)


def open_chunk_xchacha(key: bytes, nonce_prefix16: bytes, seq: int, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
    if len(key) != 32:
        raise ValueError("STREAM_KEY_LEN")
    if len(nonce_prefix16) != 16:
        raise ValueError("STREAM_NONCE_PREFIX_LEN")
    nonce = nonce_prefix16 + _le64(seq)
    return bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, aad, nonce, key)

