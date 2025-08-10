import { test } from "node:test";
import assert from "node:assert/strict";
import { createHpke, generateKeyPair, createPaymentRequired } from "../../src/index.js";

await test("createPaymentRequired helper", async (t) => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();
  const paymentRequiredData = {
    cost: "1000",
    currency: "USD",
  };
  const plaintext = new TextEncoder().encode("hello");

  await t.test("creates a private 402 response by default", async () => {
    const { envelope, publicJsonBody } = await createPaymentRequired(
      hpke,
      {
        paymentRequiredData,
        recipientPublicJwk: publicJwk,
        plaintext,
        kid: "server-key-1",
      }
    );

    assert.ok(envelope);
    assert.strictEqual(publicJsonBody, undefined);

    const opened = await hpke.open({
      recipientPrivateJwk: privateJwk,
      envelope,
      expectedKid: "server-key-1",
    });

    assert.equal(new TextDecoder().decode(opened.plaintext), "hello");
    assert.deepStrictEqual(opened.response, paymentRequiredData);
  });

  await t.test("creates a public 402 response when isPublic is true", async () => {
    const { envelope, publicJsonBody } = await createPaymentRequired(
      hpke,
      {
        paymentRequiredData,
        recipientPublicJwk: publicJwk,
        plaintext,
        kid: "server-key-1",
      },
      true // isPublic = true
    );

    assert.ok(envelope);
    assert.deepStrictEqual(publicJsonBody, paymentRequiredData);

    const opened = await hpke.open({
      recipientPrivateJwk: privateJwk,
      envelope,
      expectedKid: "server-key-1",
    });

    assert.equal(new TextDecoder().decode(opened.plaintext), "hello");
    assert.deepStrictEqual(opened.response, paymentRequiredData);
  });
});