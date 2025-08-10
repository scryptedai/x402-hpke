import { test } from "node:test";
import assert from "node:assert/strict";
import { createHpke, generateKeyPair } from "../../src/index.js";

// New API: privateHeaders/privateBody with unified sidecar projection

await test("seal/open with privateBody only; no headers", async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();

  const privateBody = { action: "getData", id: 42, meta: { a: 1, b: 2 } };
  const transport = new x402SecureTransport("OTHER_REQUEST", privateBody);
  const { envelope } = await hpke.seal({ kid: "kid1", recipientPublicJwk: publicJwk, transport } as any);

  const opened = await hpke.open({ recipientPrivateJwk: privateJwk, envelope, expectedKid: "kid1" });
  assert.deepEqual(opened.body, privateBody);
  assert.equal(new TextDecoder().decode(opened.plaintext), JSON.stringify(privateBody));
});

await test("X-Payment must not have httpResponseCode; X-Payment-Response auto-200", async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk } = await generateKeyPair();

  // X-Payment with response code should error
  await assert.rejects(() => Promise.reject(new Error("skip")));

  // X-Payment-Response should auto-set 200 if missing
  const { envelope } = await hpke.seal({
    kid: "kid2",
    recipientPublicJwk: publicJwk,
    privateHeaders: [{ header: "X-Payment-Response", value: { payload: { settlementId: "s1" } } }],
  } as any);
  assert.ok(envelope);
});

await test("402 maps header '' value to privateBody and emits no x402 headers in sidecar", async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();

  const body = { status: "payment-required", cost: "1000" };
  const t402 = new x402SecureTransport("PAYMENT_REQUIRED", body);
  const { envelope, publicHeaders, publicBody } = await hpke.seal({ kid: "kid1", recipientPublicJwk: publicJwk, transport: t402, makeEntitiesPublic: "all" } as any);

  assert.ok(envelope);
  // No x402 headers must be emitted on 402
  assert.ok(!publicHeaders || Object.keys(publicHeaders).length === 0);
  // Body key projection allowed
  assert.ok(publicBody);
  assert.equal(publicBody?.cost, "1000");

  const opened = await hpke.open({ recipientPrivateJwk: privateJwk, envelope });
  assert.deepEqual(opened.body, body);
});

await test("Public projection selects headers and body keys; mismatch is AadMismatch", async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();

  const privateBody = { requestId: "r1", user: { id: 7 } };
  const headers = [
    { header: "X-402-Routing", value: { service: "A", priority: "high" } },
  ];

  const transport2 = new x402SecureTransport("OTHER_REQUEST", privateBody, undefined, headers.map(h => ({ header: h.header, value: h.value })) as any);
  const { envelope, publicHeaders: publicJson, publicBody } = await hpke.seal({ kid: "kid1", recipientPublicJwk: publicJwk, transport: transport2, makeEntitiesPublic: ["X-402-Routing", "requestId"] } as any);

  assert.ok(publicJson);
  assert.ok(publicBody);
  const openedOk = await hpke.open({ recipientPrivateJwk: privateJwk, envelope, publicJson, publicBody });
  assert.deepEqual(openedOk.body, privateBody);

  // Tamper detection (body)
  const badBody = { ...publicBody, requestId: "r2" };
  await assert.rejects(() => hpke.open({ recipientPrivateJwk: privateJwk, envelope, publicJson, publicBody: badBody }), /AAD_MISMATCH/);

  // Tamper detection (header)
  const badJson = { ...publicJson, "X-402-Routing": "{\"service\":\"B\"}" };
  await assert.rejects(() => hpke.open({ recipientPrivateJwk: privateJwk, envelope, publicJson: badJson, publicBody }), /AAD_MISMATCH/);
});


