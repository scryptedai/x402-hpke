import { test } from "node:test";
import assert from "node:assert/strict";
import { createHpke, generateKeyPair } from "../../src/index.js";
import { readFileSync } from "node:fs";
import path from "node:path";

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
  };
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
  };
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
  };
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
  };
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
    const { envelope } = await hpke.seal({
      kid: vector.kid,
      recipientPublicJwk: publicJwk,
      plaintext: new Uint8Array(pt),
      x402: vector.x402,
      __testEphSeed32: vector.eph_seed32_b64u ? new Uint8Array(Buffer.from(vector.eph_seed32_b64u.replace(/-/g, "+").replace(/_/g, "/"), "base64")) : undefined,
    } as any);
    if (vector.envelope) {
      assert.equal(envelope.aad, vector.envelope.aad);
      assert.equal(envelope.enc, vector.envelope.enc);
      assert.equal(envelope.kid, vector.envelope.kid);
    }
    const opened = await hpke.open({ recipientPrivateJwk: privateJwk, envelope });
    assert.equal(Buffer.from(opened.plaintext).toString("base64"), Buffer.from(pt).toString("base64"));
  }
});