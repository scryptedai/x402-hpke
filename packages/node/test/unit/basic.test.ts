import { test } from "node:test";
import assert from "node:assert/strict";
import { createHpke, generateKeyPair } from "../../src/index.js";
import { readFileSync } from "node:fs";
import path from "node:path";
import { sealChunkXChaCha, openChunkXChaCha } from "../../src/streaming.js";

await test("seal/open roundtrip with request payload", async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();
  const payload = new TextEncoder().encode("hello");
  const { envelope } = await hpke.seal({
    request: { action: "test" },
    kid: "kid1",
    recipientPublicJwk: publicJwk,
    plaintext: payload,
  });
  const opened = await hpke.open({ recipientPrivateJwk: privateJwk, envelope, expectedKid: "kid1" });
  assert.equal(new TextDecoder().decode(opened.plaintext), "hello");
  assert.deepStrictEqual(opened.request, { action: "test" });
});

await test("publicJsonBody for request payload", async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();
  const payload = new TextEncoder().encode("bye");
  const { envelope, publicJsonBody } = await hpke.seal({
    request: { data: "public" },
    kid: "kid1",
    recipientPublicJwk: publicJwk,
    plaintext: payload,
    public: { makeEntitiesPublic: ["request"] },
  });
  assert.deepStrictEqual(publicJsonBody, { data: "public" });
  const opened = await hpke.open({ recipientPrivateJwk: privateJwk, envelope, expectedKid: "kid1" });
  assert.equal(new TextDecoder().decode(opened.plaintext), "bye");
});

await test("reject low-order shared secret", async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();
  const payload = new TextEncoder().encode("hi");
  const { envelope } = await hpke.seal({
    request: { data: "low_order" },
    kid: "kid1",
    recipientPublicJwk: publicJwk,
    plaintext: payload,
  });
  const encZero = Buffer.alloc(32).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  const bad = { ...envelope, enc: encZero } as typeof envelope; // 32 zero bytes
  await assert.rejects(() => hpke.open({ recipientPrivateJwk: privateJwk, envelope: bad, expectedKid: "kid1" }), /ECDH_LOW_ORDER/);
});

await test("reject AEAD mismatch and unsupported", async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();
  const payload = new TextEncoder().encode("ok");
  const { envelope } = await hpke.seal({
    request: { data: "aead" },
    kid: "kid1",
    recipientPublicJwk: publicJwk,
    plaintext: payload,
  });
  const bad = { ...envelope, aead: "AES-256-GCM" } as typeof envelope;
  await assert.rejects(() => hpke.open({ recipientPrivateJwk: privateJwk, envelope: bad, expectedKid: "kid1" }), /AEAD_MISMATCH/);
});

await test("three use cases for sidecar generation with x402", async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();
  const payload = new TextEncoder().encode("test data");

  // Case 1: Client request (no httpResponseCode) - can include X-PAYMENT in sidecar
  const { envelope: clientEnvelope, publicHeaders: clientHeaders } = await hpke.seal({
    x402: { header: "X-Payment", payload: { invoiceId: "inv_1" } },
    kid: "kid1",
    recipientPublicJwk: publicJwk,
    plaintext: payload,
    public: { makeEntitiesPublic: ["X-Payment"], as: "headers" }
  });
  assert.ok(clientHeaders);
  assert.ok(clientHeaders["X-PAYMENT"]);
  
  // Case 2: 402 response - no X-402 headers in sidecar (but body is encrypted)
  const { envelope: response402Envelope, publicHeaders: response402Headers } = await hpke.seal({
    x402: { header: "", payload: {} },
    httpResponseCode: 402,
    kid: "kid1",
    recipientPublicJwk: publicJwk,
    plaintext: payload,
    public: { makeEntitiesPublic: ["X-Payment"], as: "headers" } // This should be ignored for 402
  });
  assert.ok(response402Envelope);
  assert.strictEqual(response402Headers, undefined); // 402 responses don't send X-402 headers
  
  // Case 3: Success response (200) - can include X-PAYMENT-RESPONSE in sidecar
  const { envelope: successEnvelope, publicHeaders: successHeaders } = await hpke.seal({
    x402: { header: "X-Payment-Response", payload: { settlementId: "settle_1" } },
    httpResponseCode: 200,
    kid: "kid1",
    recipientPublicJwk: publicJwk,
    plaintext: payload,
    public: { makeEntitiesPublic: ["X-Payment-Response"], as: "headers" }
  });
  assert.ok(successHeaders);
  assert.ok(successHeaders["X-PAYMENT-RESPONSE"]);
  
  // Verify all envelopes can be opened
  const openedClient = await hpke.open({ recipientPrivateJwk: privateJwk, envelope: clientEnvelope, publicHeaders: clientHeaders });
  const opened402 = await hpke.open({ recipientPrivateJwk: privateJwk, envelope: response402Envelope });
  const openedSuccess = await hpke.open({ recipientPrivateJwk: privateJwk, envelope: successEnvelope, publicHeaders: successHeaders });
  
  assert.equal(new TextDecoder().decode(openedClient.plaintext), "test data");
  assert.equal(new TextDecoder().decode(opened402.plaintext), "test data");
  assert.equal(new TextDecoder().decode(openedSuccess.plaintext), "test data");
});

await test("KATs v1 vectors", async () => {
  const hpke = createHpke({ namespace: "myapp" });

  const katPath = path.resolve(process.cwd(), "../../docs/KATs/kat_v1.json");
  const raw = readFileSync(katPath, "utf8");
  const doc = JSON.parse(raw);
  const b64uToBytes = (s: string): Buffer => {
    if (!s) return Buffer.alloc(0);
    const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
    const pad = "===".slice((b64.length + 3) % 4);
    return Buffer.from(b64 + pad, "base64");
  };
  for (const v of doc.vectors || []) {
    const { ns, kid, request, response, x402, sidecar_as, public: pub, plaintext_b64u, eph_seed32_b64u, http_response_code } = v;
    const { publicJwk, privateJwk } = await generateKeyPair();
    const plaintext = b64uToBytes(plaintext_b64u || "");
    const seed = b64uToBytes(eph_seed32_b64u || "");
    const __testEphSeed32 = seed.length === 32 ? seed : undefined;
    const makeEntitiesPublic = Array.isArray(pub) ? pub : (pub === "all" || pub === "*" ? "all" : undefined);
    const as = sidecar_as === "json" ? "json" : "headers";
    const sealArgs: any = { kid, recipientPublicJwk: publicJwk, plaintext, __testEphSeed32 };
    if (request) sealArgs.request = request;
    if (response) sealArgs.response = response;
    if (x402) sealArgs.x402 = x402;
    if (http_response_code !== undefined) sealArgs.httpResponseCode = http_response_code;
    if (makeEntitiesPublic) sealArgs.public = { makeEntitiesPublic, as };
    const { envelope, publicHeaders, publicJson, publicJsonBody } = await hpke.seal(sealArgs);
    // Open to validate decryptability and AAD consistency
    const opened = await hpke.open({ recipientPrivateJwk: privateJwk, envelope, publicHeaders, publicJson });
    assert.ok(opened.plaintext instanceof Uint8Array);
    // If publicJsonBody expected, ensure it's not undefined
    if (Array.isArray(pub) && pub.includes("request") && request) {
      assert.deepEqual(publicJsonBody, request);
    }
    if (Array.isArray(pub) && pub.includes("response") && response) {
      assert.deepEqual(publicJsonBody, response);
    }
  }
});