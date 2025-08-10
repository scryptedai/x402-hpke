import { test } from "node:test";
import assert from "node:assert/strict";
import { createHpke, x402SecureTransport, CanonicalHeaders, generateKeyPair } from "../../src/index.js";

await test("seal() with transport: private by default, no sidecar", async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();
  const t = new x402SecureTransport("OTHER_REQUEST", { a: 1 });
  const { envelope, publicHeaders, publicBody } = await hpke.seal({
    kid: "kid1",
    recipientPublicJwk: publicJwk,
    transport: t,
  } as any);
  assert.ok(envelope);
  assert.equal(publicHeaders, undefined);
  assert.equal(publicBody, undefined);
  const opened = await hpke.open({ recipientPrivateJwk: privateJwk, envelope });
  assert.equal(new TextDecoder().decode(opened.plaintext), JSON.stringify({ a: 1 }));
});

await test("seal() with transport: makeEntitiesPublic all emits both headers/body", async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();
  const t = new x402SecureTransport("PAYMENT", { payload: { invoiceId: "inv_1" } }, undefined, [
    { header: "X-Ext", value: { foo: "bar" } },
  ]);
  const { envelope, publicHeaders, publicBody } = await hpke.seal({
    kid: "kid1",
    recipientPublicJwk: publicJwk,
    transport: t,
    makeEntitiesPublic: "all",
  } as any);
  assert.ok(publicHeaders);
  assert.ok(publicHeaders![CanonicalHeaders.X_PAYMENT]);
  assert.ok(publicHeaders!["X-Ext"]);
  assert.equal(publicBody, undefined); // PAYMENT has empty body
  const opened = await hpke.open({ recipientPrivateJwk: privateJwk, envelope, publicHeaders });
  assert.ok(opened);
});

await test("seal() with transport: list selection for headers and body keys", async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();
  const t = new x402SecureTransport("OTHER_RESPONSE", { a: 1, b: 2 }, 200, [
    { header: "X-Alpha", value: { A: true } },
    { header: "X-Beta", value: { B: true } },
  ]);
  const { envelope, publicHeaders, publicBody } = await hpke.seal({
    kid: "kid1",
    recipientPublicJwk: publicJwk,
    transport: t,
    makeEntitiesPublic: ["X-Alpha", "b"],
  } as any);
  assert.deepEqual(publicHeaders, { "X-Alpha": "{\"A\":true}" });
  assert.deepEqual(publicBody, { b: 2 });
  const opened = await hpke.open({ recipientPrivateJwk: privateJwk, envelope, publicHeaders, publicBody });
  assert.equal(new TextDecoder().decode(opened.plaintext), JSON.stringify({ a: 1, b: 2 }));
});

await test("seal() with transport: 402 never emits core payment headers in sidecar", async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();
  const t = new x402SecureTransport("PAYMENT_REQUIRED", { need: true });
  const { envelope, publicHeaders, publicBody } = await hpke.seal({
    kid: "kid1",
    recipientPublicJwk: publicJwk,
    transport: t,
    makeEntitiesPublic: "all",
  } as any);
  assert.equal(publicHeaders, undefined); // no core headers in sidecar for 402
  assert.deepEqual(publicBody, { need: true });
  const opened = await hpke.open({ recipientPrivateJwk: privateJwk, envelope, publicBody });
  assert.equal(new TextDecoder().decode(opened.plaintext), JSON.stringify({ need: true }));
});


