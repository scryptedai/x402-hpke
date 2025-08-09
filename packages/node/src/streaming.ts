import sodium from "libsodium-wrappers";

export type StreamingKey = Uint8Array; // 32 bytes

function le64(n: number): Uint8Array {
  const b = new Uint8Array(8);
  let x = BigInt(n);
  for (let i = 0; i < 8; i++) {
    b[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return b;
}

export async function sealChunkXChaCha(
  key: StreamingKey,
  noncePrefix16: Uint8Array,
  seq: number,
  plaintext: Uint8Array,
  aad?: Uint8Array
): Promise<Uint8Array> {
  await sodium.ready;
  if (noncePrefix16.length !== 16) throw new Error("STREAM_NONCE_PREFIX_LEN");
  const nonce = new Uint8Array(24);
  nonce.set(noncePrefix16, 0);
  nonce.set(le64(seq), 16);
  return sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad ?? null, null, nonce, key);
}

export async function openChunkXChaCha(
  key: StreamingKey,
  noncePrefix16: Uint8Array,
  seq: number,
  ciphertext: Uint8Array,
  aad?: Uint8Array
): Promise<Uint8Array> {
  await sodium.ready;
  if (noncePrefix16.length !== 16) throw new Error("STREAM_NONCE_PREFIX_LEN");
  const nonce = new Uint8Array(24);
  nonce.set(noncePrefix16, 0);
  nonce.set(le64(seq), 16);
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, aad ?? null, nonce, key);
}

export class XChaChaStreamLimiter {
  private readonly key: StreamingKey;
  private readonly prefix: Uint8Array;
  private readonly maxChunks: number;
  private readonly maxBytes: number;
  private chunksUsed = 0;
  private bytesUsed = 0;

  constructor(key: StreamingKey, noncePrefix16: Uint8Array, opts?: { maxChunks?: number; maxBytes?: number }) {
    if (noncePrefix16.length !== 16) throw new Error("STREAM_NONCE_PREFIX_LEN");
    this.key = key;
    this.prefix = noncePrefix16;
    this.maxChunks = opts?.maxChunks ?? 1_000_000; // implementation-chosen default
    this.maxBytes = opts?.maxBytes ?? 1_000_000_000; // implementation-chosen default
  }

  private enforceLimits(nextBytes: number) {
    if (this.chunksUsed + 1 > this.maxChunks) throw new Error("AEAD_LIMIT");
    if (this.bytesUsed + nextBytes > this.maxBytes) throw new Error("AEAD_LIMIT");
  }

  async seal(seq: number, chunk: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
    this.enforceLimits(chunk.length);
    const ct = await sealChunkXChaCha(this.key, this.prefix, seq, chunk, aad);
    this.chunksUsed += 1;
    this.bytesUsed += chunk.length;
    return ct;
  }

  async open(seq: number, ct: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
    // Limits are typically enforced on sealers; accepters may optionally enforce bytes
    return openChunkXChaCha(this.key, this.prefix, seq, ct, aad);
  }
}