import { test } from "node:test";
import assert from "node:assert/strict";
import { createHpke, generateKeyPair } from "../../src/index.js";

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