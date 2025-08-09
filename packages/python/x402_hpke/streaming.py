from __future__ import annotations
from typing import Optional
from .errors import (
    SeqNegative,
    StreamKeyLen,
    StreamNoncePrefixLen,
    AeadLimit,
)
from nacl import bindings


def _le64(n: int) -> bytes:
    if n < 0:
        raise SeqNegative("SEQ_NEGATIVE")
    b = bytearray(8)
    x = n
    for i in range(8):
        b[i] = x & 0xFF
        x >>= 8
    return bytes(b)


def seal_chunk_xchacha(key: bytes, nonce_prefix16: bytes, seq: int, chunk: bytes, aad: Optional[bytes] = None) -> bytes:
    if len(key) != 32:
        raise StreamKeyLen("STREAM_KEY_LEN")
    if len(nonce_prefix16) != 16:
        raise StreamNoncePrefixLen("STREAM_NONCE_PREFIX_LEN")
    nonce = nonce_prefix16 + _le64(seq)
    return bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(chunk, aad, nonce, key)


def open_chunk_xchacha(key: bytes, nonce_prefix16: bytes, seq: int, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
    if len(key) != 32:
        raise StreamKeyLen("STREAM_KEY_LEN")
    if len(nonce_prefix16) != 16:
        raise StreamNoncePrefixLen("STREAM_NONCE_PREFIX_LEN")
    nonce = nonce_prefix16 + _le64(seq)
    return bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, aad, nonce, key)

class XChaChaStreamLimiter:
    def __init__(self, key: bytes, nonce_prefix16: bytes, max_chunks: int = 1_000_000, max_bytes: int = 1_000_000_000) -> None:
        if len(key) != 32:
            raise ValueError("STREAM_KEY_LEN")
        if len(nonce_prefix16) != 16:
            raise ValueError("STREAM_NONCE_PREFIX_LEN")
        self._key = key
        self._prefix = nonce_prefix16
        self._max_chunks = max_chunks
        self._max_bytes = max_bytes
        self._chunks_used = 0
        self._bytes_used = 0

    def _enforce(self, next_bytes: int) -> None:
        if self._chunks_used + 1 > self._max_chunks:
            raise AeadLimit("AEAD_LIMIT")
        if self._bytes_used + next_bytes > self._max_bytes:
            raise AeadLimit("AEAD_LIMIT")

    def seal(self, seq: int, chunk: bytes, aad: Optional[bytes] = None) -> bytes:
        self._enforce(len(chunk))
        ct = seal_chunk_xchacha(self._key, self._prefix, seq, chunk, aad)
        self._chunks_used += 1
        self._bytes_used += len(chunk)
        return ct

    def open(self, seq: int, ct: bytes, aad: Optional[bytes] = None) -> bytes:
        return open_chunk_xchacha(self._key, self._prefix, seq, ct, aad)