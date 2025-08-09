# Streaming Encryption (exported key)

- Export streaming key from HPKE context: `export("stream:v1", 32)` (explicit export API is planned; for now, applications must derive a key/nonce prefix out-of-band or via application contract).
- AEAD: XChaCha20-Poly1305 via libsodium.
- Nonce: 24 bytes = `prefix(16) || le64(seq)`.
- Each chunk: `{ seq, ct }` with AEAD tag included; reject out-of-order or duplicate seq.
- Rekey before large seq windows; no compression.

Limits (normative)
- Enforce a maximum number of chunks per context (implementation-chosen constant) and/or maximum bytes.
- Exceeding limits MUST fail closed with `AEAD_LIMIT`.

Availability
- Node: `sealChunkXChaCha(key, prefix16, seq, chunk, aad?)`, `openChunkXChaCha(key, prefix16, seq, ct, aad?)`.
- Python: `seal_chunk_xchacha(key, prefix16, seq, chunk, aad=None)`, `open_chunk_xchacha(key, prefix16, seq, ct, aad=None)`.

Limit-enforcing wrappers
- Node: `new XChaChaStreamLimiter(key, prefix16, { maxChunks?, maxBytes? })` with `.seal(seq, chunk, aad?)` and `.open(seq, ct, aad?)`.
- Python: `XChaChaStreamLimiter(key, prefix16, max_chunks=..., max_bytes=...)` with `.seal(seq, chunk, aad=None)` and `.open(seq, ct, aad=None)`.

API (vNext)
- Provide `exportStreamingKey(info?: string) -> bytes` and `exportNoncePrefix16(info?: string) -> bytes` on the HPKE context to standardize derivation.