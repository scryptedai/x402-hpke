# Streaming Encryption (XChaCha20-Poly1305)

Streaming encryption is implemented using XChaCha20-Poly1305 with a 24-byte nonce constructed as `prefix(16) || le64(seq)`.

## Basic Chunk Operations

### Node.js

```typescript
import { sealChunkXChaCha, openChunkXChaCha } from "@x402-hpke/node";

// Encrypt a chunk
const ct = await sealChunkXChaCha(key, prefix16, seq, chunk, aad?);

// Decrypt a chunk  
const pt = await openChunkXChaCha(key, prefix16, seq, ct, aad?);
```

### Python

```python
from x402_hpke import seal_chunk_xchacha, open_chunk_xchacha

# Encrypt a chunk
ct = seal_chunk_xchacha(key, prefix16, seq, chunk, aad=None)

# Decrypt a chunk
pt = open_chunk_xchacha(key, prefix16, seq, ct, aad=None)
```

## Nonce Construction

- **Nonce**: 24 bytes = `prefix(16) || le64(seq)`
- **Prefix**: 16-byte application-specific prefix (e.g., random bytes, session ID)
- **Sequence**: 64-bit little-endian sequence number starting from 0
- **AAD**: Optional associated data for each chunk

## Limit-Enforcing Wrappers

The library provides limit-enforcing wrappers to prevent abuse:

### Node.js

```typescript
import { XChaChaStreamLimiter } from "@x402-hpke/node";

const limiter = new XChaChaStreamLimiter(key, prefix16, { 
  maxChunks: 1000,      // Maximum number of chunks
  maxBytes: 1000000     // Maximum total bytes
});

// Encrypt with limits enforced
const ct = await limiter.seal(seq, chunk, aad?);

// Decrypt (limits typically enforced on sealers)
const pt = await limiter.open(seq, ct, aad?);
```

### Python

```python
from x402_hpke import XChaChaStreamLimiter

limiter = XChaChaStreamLimiter(
    key, 
    prefix16, 
    max_chunks=1000,    # Maximum number of chunks
    max_bytes=1000000   # Maximum total bytes
)

# Encrypt with limits enforced
ct = limiter.seal(seq, chunk, aad=None)

# Decrypt (limits typically enforced on sealers)
pt = limiter.open(seq, ct, aad=None)
```

## Implementation Details

- **AEAD**: XChaCha20-Poly1305 via libsodium (Node) / PyNaCl (Python)
- **Key derivation**: Applications must derive the streaming key out-of-band or via application contract
- **Sequence validation**: Reject out-of-order or duplicate sequence numbers
- **Limit enforcement**: Fail closed with `AEAD_LIMIT` when limits exceeded
- **No compression**: Raw chunk encryption without compression

## Usage Patterns

### 1. Basic Streaming

```typescript
// Derive key from HPKE context (application-specific)
const streamingKey = deriveStreamingKey(hpkeContext);

// Encrypt chunks sequentially
for (let seq = 0; seq < chunks.length; seq++) {
  const ct = await sealChunkXChaCha(streamingKey, prefix16, seq, chunks[seq]);
  // Send ct to recipient
}
```

### 2. With Limits

```typescript
const limiter = new XChaChaStreamLimiter(streamingKey, prefix16, {
  maxChunks: 10000,
  maxBytes: 10000000  // 10MB
});

try {
  for (let seq = 0; seq < chunks.length; seq++) {
    const ct = await limiter.seal(seq, chunks[seq]);
    // Send ct to recipient
  }
} catch (error) {
  if (error.code === 'AEAD_LIMIT') {
    // Handle limit exceeded
  }
}
```

### 3. Chunk Validation

```typescript
// Recipient side
const receivedChunks = new Set<number>();

for (const { seq, ct } of incomingChunks) {
  if (receivedChunks.has(seq)) {
    throw new Error('Duplicate sequence number');
  }
  
  const pt = await openChunkXChaCha(streamingKey, prefix16, seq, ct);
  receivedChunks.add(seq);
  
  // Process plaintext chunk
}
```

## Security Considerations

- **Nonce uniqueness**: Each (key, prefix, seq) combination must be unique
- **Sequence validation**: Reject out-of-order or duplicate sequences
- **Key management**: Use separate keys for different streams
- **Limit enforcement**: Implement application-specific limits to prevent abuse
- **Replay protection**: Sequence numbers provide basic replay protection within a stream

## Future Enhancements

Future versions may include:
- Standardized key export APIs on HPKE context
- Additional AEAD algorithms (AES-GCM, etc.)
- Compression support
- Multi-stream management
- Built-in sequence validation and ordering