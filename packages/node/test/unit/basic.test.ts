import { test } from "node:test";
import assert from "node:assert/strict";
import { createHpke, generateKeyPair } from "../../src/index.js";
import { readFileSync } from "node:fs";
import path from "node:path";
import { sealChunkXChaCha, openChunkXChaCha } from "../../src/streaming.js";

await test("seal/open roundtrip", async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();
  const x402 = {
    invoiceId: "inv_1",
    chainId: 8453,
    tokenContract: "0x" + "a".repeat(40),
    amount: "1000",
    recipient: "0x" + "b".repeat(40),
    txHash: "0x" + "c".repeat(64),
    expiry: 9999999999,
    priceHash: "0x" + "d".repeat(64),
  } as any;
  x402.replyToJwk = publicJwk;
  const payload = new TextEncoder().encode("hello");
  const { envelope } = await hpke.seal({ kid: "kid1", recipientPublicJwk: publicJwk, plaintext: payload, x402 });
  const opened = await hpke.open({ recipientPrivateJwk: privateJwk, envelope, expectedKid: "kid1" });
  assert.equal(new TextDecoder().decode(opened.plaintext), "hello");
  assert.equal(opened.x402.invoiceId, x402.invoiceId);
});

await test("header sidecar AAD equivalence", async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();
  const x402 = {
    invoiceId: "inv_2",
    chainId: 8453,
    tokenContract: "0x" + "a".repeat(40),
    amount: "2000",
    recipient: "0x" + "b".repeat(40),
    txHash: "0x" + "c".repeat(64),
    expiry: 9999999900,
    priceHash: "0x" + "d".repeat(64),
  } as any;
  x402.replyToJwk = publicJwk;
  const payload = new TextEncoder().encode("bye");
  const { envelope, publicHeaders } = await hpke.seal({ kid: "kid1", recipientPublicJwk: publicJwk, plaintext: payload, x402, public: { x402Headers: true, as: "headers" } });
  assert.ok(publicHeaders);
  const opened = await hpke.open({ recipientPrivateJwk: privateJwk, envelope, expectedKid: "kid1", publicHeaders });
  assert.equal(new TextDecoder().decode(opened.plaintext), "bye");
});

await test("reject low-order shared secret", async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();
  const x402 = {
    invoiceId: "inv_low",
    chainId: 8453,
    tokenContract: "0x" + "a".repeat(40),
    amount: "1000",
    recipient: "0x" + "b".repeat(40),
    txHash: "0x" + "c".repeat(64),
    expiry: 9999999999,
    priceHash: "0x" + "d".repeat(64),
  } as any;
  x402.replyToJwk = publicJwk;
  const payload = new TextEncoder().encode("hi");
  const { envelope } = await hpke.seal({ kid: "kid1", recipientPublicJwk: publicJwk, plaintext: payload, x402 });
  const encZero = Buffer.alloc(32).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  const bad = { ...envelope, enc: encZero } as typeof envelope; // 32 zero bytes
  await assert.rejects(() => hpke.open({ recipientPrivateJwk: privateJwk, envelope: bad, expectedKid: "kid1" }), /ECDH_LOW_ORDER/);
});

await test("reject AEAD mismatch and unsupported", async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();
  const x402 = {
    invoiceId: "inv_aead",
    chainId: 8453,
    tokenContract: "0x" + "a".repeat(40),
    amount: "1000",
    recipient: "0x" + "b".repeat(40),
    txHash: "0x" + "c".repeat(64),
    expiry: 9999999999,
    priceHash: "0x" + "d".repeat(64),
  } as any;
  x402.replyToJwk = publicJwk;
  const payload = new TextEncoder().encode("ok");
  const { envelope } = await hpke.seal({ kid: "kid1", recipientPublicJwk: publicJwk, plaintext: payload, x402 });
  const bad = { ...envelope, aead: "AES-256-GCM" } as typeof envelope;
  await assert.rejects(() => hpke.open({ recipientPrivateJwk: privateJwk, envelope: bad, expectedKid: "kid1" }), /AEAD_MISMATCH/);
});

await test("KAT: known-answer vectors", async () => {
  const katPath = path.resolve(process.cwd(), "docs", "KATs", "kat_v1.json");
  let kat: any;
  try {
    kat = JSON.parse(readFileSync(katPath, "utf8"));
  } catch {
    // Skip if no KATs yet
    return;
  }
  for (const vector of kat.vectors ?? []) {
    const hpke = createHpke({ namespace: vector.ns });
    const { publicJwk, privateJwk } = await generateKeyPair();
    // Re-seal using deterministic eph seed if provided
    const pt = Buffer.from(vector.plaintext_b64u.replace(/-/g, "+").replace(/_/g, "/"), "base64");
    const sealArgs: any = {
      kid: vector.kid,
      recipientPublicJwk: publicJwk,
      plaintext: new Uint8Array(pt),
      x402: vector.x402,
      __testEphSeed32: vector.eph_seed32_b64u ? new Uint8Array(Buffer.from(vector.eph_seed32_b64u.replace(/-/g, "+").replace(/_/g, "/"), "base64")) : undefined,
    };
    if (vector.app) sealArgs.app = vector.app;
    if (vector.allowlist || vector.sidecar_as) sealArgs.public = { x402Headers: true, appHeaderAllowlist: vector.allowlist || [], as: vector.sidecar_as || "headers" };
    const { envelope, publicHeaders, publicJson } = await hpke.seal(sealArgs);
    if (vector.envelope) {
      assert.equal(envelope.aad, vector.envelope.aad);
      assert.equal(envelope.enc, vector.envelope.enc);
      assert.equal(envelope.kid, vector.envelope.kid);
    }
    const opened = await hpke.open({ recipientPrivateJwk: privateJwk, envelope, publicHeaders, publicJson });
    assert.equal(Buffer.from(opened.plaintext).toString("base64"), Buffer.from(pt).toString("base64"));
  }
});

await test("KAT: streaming vectors", async () => {
  const katPath = path.resolve(process.cwd(), "docs", "KATs", "kat_stream_v1.json");
  let kat: any;
  try {
    kat = JSON.parse(readFileSync(katPath, "utf8"));
  } catch {
    return;
  }
  for (const v of kat.vectors ?? []) {
    const key = Buffer.from(v.key_b64u.replace(/-/g, "+").replace(/_/g, "/"), "base64");
    const prefix = Buffer.from(v.prefix16_b64u.replace(/-/g, "+").replace(/_/g, "/"), "base64");
    const aad = v.aad_b64u ? Buffer.from(v.aad_b64u.replace(/-/g, "+").replace(/_/g, "/"), "base64") : null;
    const plains = v.chunks_b64u.map((b64: string) => new Uint8Array(Buffer.from(b64.replace(/-/g, "+").replace(/_/g, "/"), "base64")));
    const cts: Uint8Array[] = [];
    let seq = v.start_seq || 0;
    for (const chunk of plains) {
      const ct = await sealChunkXChaCha(new Uint8Array(key), new Uint8Array(prefix), seq, chunk, aad ?? undefined);
      cts.push(ct);
      seq += 1;
    }
    seq = v.start_seq || 0;
    for (let i = 0; i < cts.length; i++) {
      const pt = await openChunkXChaCha(new Uint8Array(key), new Uint8Array(prefix), seq, cts[i], aad ?? undefined);
      assert.equal(Buffer.from(pt).toString("base64"), Buffer.from(plains[i]).toString("base64"));
      seq += 1;
    }
  }
});

await test("KAT: negative vectors (envelope)", async () => {
  const katPath = path.resolve(process.cwd(), "docs", "KATs", "kat_v1_negative.json");
  let kat: any;
  try {
    kat = JSON.parse(readFileSync(katPath, "utf8"));
  } catch {
    return;
  }
  for (const v of kat.vectors ?? []) {
    const hpke = createHpke({ namespace: v.ns });
    const { publicJwk } = await generateKeyPair();
    const pt = Buffer.from(v.plaintext_b64u.replace(/-/g, "+").replace(/_/g, "/"), "base64");
    const sealArgs: any = {
      kid: v.kid,
      recipientPublicJwk: publicJwk,
      plaintext: new Uint8Array(pt),
      x402: v.x402,
    };
    if (v.app) sealArgs.app = v.app;
    if (v.allowlist) sealArgs.public = { x402Headers: true, appHeaderAllowlist: v.allowlist, as: "headers" };
    await assert.rejects(() => hpke.seal(sealArgs), new RegExp(v.expected_error));
  }
});

await test("KAT: negative vectors (streaming)", async () => {
  const katPath = path.resolve(process.cwd(), "docs", "KATs", "kat_stream_v1_negative.json");
  let kat: any;
  try {
    kat = JSON.parse(readFileSync(katPath, "utf8"));
  } catch {
    return;
  }
  for (const v of kat.vectors ?? []) {
    const key = Buffer.from(v.key_b64u.replace(/-/g, "+").replace(/_/g, "/"), "base64");
    const prefix = Buffer.from(v.prefix16_b64u.replace(/-/g, "+").replace(/_/g, "/"), "base64");
    const limiter = new (await import("../../src/streaming.js")).XChaChaStreamLimiter(new Uint8Array(key), new Uint8Array(prefix), { maxChunks: v.max_chunks ?? 1000000 });
    await limiter.seal(0, new TextEncoder().encode("ch1"));
    if (v.max_chunks === 1) {
      await assert.rejects(() => limiter.seal(1, new TextEncoder().encode("ch2")), /AEAD_LIMIT/);
    }
  }
});

await test("reject seal without reply-to", async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk } = await generateKeyPair();
  const x402 = {
    invoiceId: "inv_nort",
    chainId: 8453,
    tokenContract: "0x" + "a".repeat(40),
    amount: "1",
    recipient: "0x" + "b".repeat(40),
    txHash: "0x" + "c".repeat(64),
    expiry: 9999999999,
    priceHash: "0x" + "d".repeat(64),
  } as any;
  const payload = new TextEncoder().encode("no-rt");
  await assert.rejects(() => hpke.seal({ kid: "kid1", recipientPublicJwk: publicJwk, plaintext: payload, x402 }), /REPLY_TO_REQUIRED/);
});

await test("forbid replyTo*/replyPublicOk in sidecar allowlist", async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk } = await generateKeyPair();
  const x402 = {
    invoiceId: "inv_forbid",
    chainId: 8453,
    tokenContract: "0x" + "a".repeat(40),
    amount: "2",
    recipient: "0x" + "b".repeat(40),
    txHash: "0x" + "c".repeat(64),
    expiry: 9999999999,
    priceHash: "0x" + "d".repeat(64),
    replyToJwk: publicJwk,
  } as any;
  const app = { traceId: "abc", replyPublicOk: true } as any;
  const payload = new TextEncoder().encode("forbid");
  await assert.rejects(
    () =>
      hpke.seal({
        kid: "kid1",
        recipientPublicJwk: publicJwk,
        plaintext: payload,
        x402,
        app,
        public: { x402Headers: true, appHeaderAllowlist: ["replyPublicOk"], as: "headers" },
      }),
    /REPLY_TO_SIDECAR_FORBIDDEN/
  );
});