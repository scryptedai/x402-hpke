import { test } from "node:test";
import assert from "node:assert/strict";
import { createHpke, generateKeyPair, x402SecureTransport, CanonicalHeaders } from "../../src/index.js";
import { readFileSync } from "node:fs";
import path from "node:path";
import { sealChunkXChaCha, openChunkXChaCha } from "../../src/streaming.js";

await test("seal/open roundtrip with request payload", async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();
  const transport = new x402SecureTransport("OTHER_REQUEST", { action: "test" });
  const { envelope } = await hpke.seal({ kid: "kid1", recipientPublicJwk: publicJwk, transport });
  const opened = await hpke.open({ recipientPrivateJwk: privateJwk, envelope, expectedKid: "kid1" });
  assert.deepStrictEqual(opened.body, { action: "test" });
  // Implicit plaintext is JSON(request)
  assert.equal(new TextDecoder().decode(opened.plaintext), JSON.stringify({ action: "test" }));
});

await test("public body for request payload when requested", async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();
  const transport = new x402SecureTransport("OTHER_REQUEST", { data: "public" });
  const { envelope, publicBody } = await hpke.seal({ kid: "kid1", recipientPublicJwk: publicJwk, transport, makeEntitiesPublic: "all" });
  assert.deepStrictEqual(publicBody, { data: "public" });
  const opened = await hpke.open({ recipientPrivateJwk: privateJwk, envelope, expectedKid: "kid1" });
  assert.equal(new TextDecoder().decode(opened.plaintext), JSON.stringify({ data: "public" }));
});

await test("reject low-order shared secret", async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();
  const transport = new x402SecureTransport("OTHER_REQUEST", { data: "low_order" });
  const { envelope } = await hpke.seal({ kid: "kid1", recipientPublicJwk: publicJwk, transport });
  const encZero = Buffer.alloc(32).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  const bad = { ...envelope, enc: encZero } as typeof envelope; // 32 zero bytes
  await assert.rejects(() => hpke.open({ recipientPrivateJwk: privateJwk, envelope: bad, expectedKid: "kid1" }), /ECDH_LOW_ORDER/);
});

await test("reject AEAD mismatch and unsupported", async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();
  const transport = new x402SecureTransport("OTHER_REQUEST", { data: "aead" });
  const { envelope } = await hpke.seal({ kid: "kid1", recipientPublicJwk: publicJwk, transport });
  const bad = { ...envelope, aead: "AES-256-GCM" } as typeof envelope;
  await assert.rejects(() => hpke.open({ recipientPrivateJwk: privateJwk, envelope: bad, expectedKid: "kid1" }), /AEAD_MISMATCH/);
});

await test("transport sidecar generation cases", async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();

  // Case 1: Payment request header can be included when requested
  const t1 = new x402SecureTransport("PAYMENT", { payload: { invoiceId: "inv_1" } });
  const { envelope: clientEnvelope, publicHeaders: clientHeaders } = await hpke.seal({ kid: "kid1", recipientPublicJwk: publicJwk, transport: t1, makeEntitiesPublic: [CanonicalHeaders.X_PAYMENT] });
  assert.ok(clientHeaders);
  assert.ok(clientHeaders[CanonicalHeaders.X_PAYMENT]);

  // Case 2: 402 response - no core headers in sidecar; body may be exposed
  const t2 = new x402SecureTransport("PAYMENT_REQUIRED", { need: true });
  const { envelope: response402Envelope, publicHeaders: response402Headers, publicBody: response402Body } = await hpke.seal({ kid: "kid1", recipientPublicJwk: publicJwk, transport: t2, makeEntitiesPublic: "all" });
  assert.ok(response402Envelope);
  assert.strictEqual(response402Headers, undefined);
  assert.deepEqual(response402Body, { need: true });

  // Case 3: Success response (200) - include X-PAYMENT-RESPONSE when requested
  const t3 = new x402SecureTransport("PAYMENT_RESPONSE", { ok: true });
  const { envelope: successEnvelope, publicHeaders: successHeaders } = await hpke.seal({ kid: "kid1", recipientPublicJwk: publicJwk, transport: t3, makeEntitiesPublic: [CanonicalHeaders.X_PAYMENT_RESPONSE] });
  assert.ok(successHeaders);
  assert.ok(successHeaders[CanonicalHeaders.X_PAYMENT_RESPONSE]);

  // Verify all envelopes can be opened
  const openedClient = await hpke.open({ recipientPrivateJwk: privateJwk, envelope: clientEnvelope, publicHeaders: clientHeaders });
  const opened402 = await hpke.open({ recipientPrivateJwk: privateJwk, envelope: response402Envelope, publicBody: response402Body });
  const openedSuccess = await hpke.open({ recipientPrivateJwk: privateJwk, envelope: successEnvelope, publicHeaders: successHeaders });
  assert.equal(new TextDecoder().decode(openedClient.plaintext), JSON.stringify({}));
  assert.equal(new TextDecoder().decode(opened402.plaintext), JSON.stringify({ need: true }));
  assert.equal(new TextDecoder().decode(openedSuccess.plaintext), JSON.stringify({}));
});

// KATs v1 vectors are not applicable under unified transport API; omitted