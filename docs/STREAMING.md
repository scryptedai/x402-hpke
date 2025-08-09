# Streaming Encryption (exported key)

- Export streaming key from HPKE context: `export("stream:v1", 32)` (API TBD).
- Recommended AEAD: XChaCha20-Poly1305 via libsodium.
- Nonce: 24 bytes = `prefix(16) || le64(seq)`.
- Each chunk: `{ seq, ct }` with AEAD tag included; reject out-of-order or duplicate seq.
- Rekey before large seq windows; no compression.

API (vNext):
- Node/Python: `exportStreamingKey(info?: string) -> bytes`
- Helpers to seal/open chunk with monotonic `seq`.