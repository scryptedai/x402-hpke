import { test } from "node:test";
import assert from "node:assert/strict";
import { x402SecureTransport, TransportType } from "../../src/x402SecureTransport.js";
import { CanonicalHeaders } from "../../src/constants.js";

await test("OTHER_REQUEST: rejects httpResponseCode and maps to body only", async () => {
  assert.throws(() => new x402SecureTransport("OTHER_REQUEST" satisfies TransportType, { a: 1 }, 200), /OTHER_REQUEST_HTTP_CODE/);
  const t = new x402SecureTransport("OTHER_REQUEST", { a: 1 });
  assert.equal(t.getHttpResponseCode(), undefined);
  assert.deepEqual(t.getBody(), { a: 1 });
  assert.equal(t.getHeader(), undefined);
  assert.deepEqual(t.getExtensions(), []);
});

await test("OTHER_RESPONSE: rejects 402, accepts 200, maps to body only", async () => {
  assert.throws(() => new x402SecureTransport("OTHER_RESPONSE", { ok: true }, 402), /OTHER_RESPONSE_402/);
  const t = new x402SecureTransport("OTHER_RESPONSE", { ok: true }, 200);
  assert.equal(t.getHttpResponseCode(), 200);
  assert.deepEqual(t.getBody(), { ok: true });
  assert.equal(t.getHeader(), undefined);
});

await test("PAYMENT_REQUIRED: requires non-empty content, autocorrects to 402 with warn", async () => {
  assert.throws(() => new x402SecureTransport("PAYMENT_REQUIRED", {}), /PAYMENT_REQUIRED_CONTENT/);
  const warnSpy: Array<string> = [];
  const origWarn = console.warn;
  console.warn = (msg?: any) => { warnSpy.push(String(msg || "")); };
  try {
    const t = new x402SecureTransport("PAYMENT_REQUIRED", { need: true }, 200);
    assert.equal(t.getHttpResponseCode(), 402);
    assert.ok(warnSpy.some(s => s.includes("PAYMENT_REQUIRED_HTTP_CODE_WARN")));
    assert.deepEqual(t.getBody(), { need: true });
    assert.equal(t.getHeader(), undefined);
  } finally {
    console.warn = origWarn;
  }
});

await test("PAYMENT_RESPONSE: requires non-empty content, sets 200, rejects mismatched", async () => {
  assert.throws(() => new x402SecureTransport("PAYMENT_RESPONSE", {}), /PAYMENT_RESPONSE_CONTENT/);
  assert.throws(() => new x402SecureTransport("PAYMENT_RESPONSE", { ok: true }, 204), /PAYMENT_RESPONSE_HTTP_CODE/);
  const t = new x402SecureTransport("PAYMENT_RESPONSE", { ok: true });
  assert.equal(t.getHttpResponseCode(), 200);
  assert.deepEqual(t.getHeader(), { header: CanonicalHeaders.X_PAYMENT_RESPONSE, value: { ok: true } });
  assert.deepEqual(t.getBody(), {});
});

await test("PAYMENT: requires payload key; rejects httpResponseCode; maps to header only", async () => {
  assert.throws(() => new x402SecureTransport("PAYMENT", { not_payload: true }), /PAYMENT_PAYLOAD/);
  assert.throws(() => new x402SecureTransport("PAYMENT", { payload: { id: 1 } }, 200), /PAYMENT_HTTP_CODE/);
  const t = new x402SecureTransport("PAYMENT", { payload: { id: 1 } });
  assert.equal(t.getHttpResponseCode(), undefined);
  assert.deepEqual(t.getHeader(), { header: CanonicalHeaders.X_PAYMENT, value: { payload: { id: 1 } } });
  assert.deepEqual(t.getBody(), {});
});

await test("extensions are stored and retrievable", async () => {
  const exts = [
    { header: "X-Example", value: { a: 1 } },
    { header: "X-Another", value: "b" },
  ];
  const t = new x402SecureTransport("OTHER_REQUEST", { z: 1 }, undefined, exts);
  assert.deepEqual(t.getExtensions(), exts);
});


