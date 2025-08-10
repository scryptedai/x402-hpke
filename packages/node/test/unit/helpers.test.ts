import { test } from "node:test";
import assert from "node:assert/strict";
import { 
  createHpke,
  generateKeyPair,
  createPaymentRequired,
  createPayment,
  createPaymentResponse,
  createRequest,
  createResponse,
} from "../../src/index.js";
import { registerApprovedExtensionHeader } from "../../src/extensions.js";
import * as extensions from "../../src/extensions.js";

await test("createPaymentRequired helper", async (t) => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();
  const paymentRequiredData = {
    cost: "1000",
    currency: "USD",
  };

  await t.test("creates a private 402 response by default", async () => {
    const { envelope, publicJsonBody } = await createPaymentRequired(
      hpke,
      {
        paymentRequiredData,
        recipientPublicJwk: publicJwk,
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

    assert.equal(new TextDecoder().decode(opened.plaintext), JSON.stringify(paymentRequiredData));
    assert.deepStrictEqual(opened.body, paymentRequiredData);
  });

  await t.test("creates a public 402 response when isPublic is true", async () => {
    const { envelope, publicJsonBody } = await createPaymentRequired(
      hpke,
      {
        paymentRequiredData,
        recipientPublicJwk: publicJwk,
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

    assert.equal(new TextDecoder().decode(opened.plaintext), JSON.stringify(paymentRequiredData));
    assert.deepStrictEqual(opened.body, paymentRequiredData);
  });
});

await test("createPayment helper", async (t) => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();
  const paymentData = {
    invoiceId: "inv_123",
  };

  await t.test("creates a private payment request by default", async () => {
    const { envelope, publicHeaders } = await createPayment(
      hpke,
      {
        paymentData,
        recipientPublicJwk: publicJwk,
        kid: "server-key-1",
      }
    );

    assert.ok(envelope);
    assert.strictEqual(publicHeaders, undefined);

    const opened = await hpke.open({
      recipientPrivateJwk: privateJwk,
      envelope,
      expectedKid: "server-key-1",
    });

    assert.equal(new TextDecoder().decode(opened.plaintext), JSON.stringify({}));
    assert.deepStrictEqual(opened.body, {});
  });

  await t.test("creates a public payment request when isPublic is true", async () => {
    const { envelope, publicHeaders } = await createPayment(
      hpke,
      {
        paymentData,
        recipientPublicJwk: publicJwk,
        kid: "server-key-1",
      },
      true // isPublic = true
    );

    assert.ok(envelope);
    assert.ok(publicHeaders["X-PAYMENT"]);

    const opened = await hpke.open({
      recipientPrivateJwk: privateJwk,
      envelope,
      expectedKid: "server-key-1",
      publicHeaders,
    });

    assert.equal(new TextDecoder().decode(opened.plaintext), JSON.stringify({}));
    assert.deepStrictEqual(opened.body, {});
  });
});

await test("createPaymentResponse helper", async (t) => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();
  const settlementData = {
    settlementId: "settle_123",
  };

  await t.test("creates a private payment response by default", async () => {
    const { envelope, publicHeaders } = await createPaymentResponse(
      hpke,
      {
        settlementData,
        recipientPublicJwk: publicJwk,
        kid: "server-key-1",
      }
    );

    assert.ok(envelope);
    assert.strictEqual(publicHeaders, undefined);

    const opened = await hpke.open({
      recipientPrivateJwk: privateJwk,
      envelope,
      expectedKid: "server-key-1",
    });

    assert.equal(new TextDecoder().decode(opened.plaintext), JSON.stringify({}));
    assert.deepStrictEqual(opened.body, {});
  });

  await t.test("creates a public payment response when isPublic is true", async () => {
    const { envelope, publicHeaders } = await createPaymentResponse(
      hpke,
      {
        settlementData,
        recipientPublicJwk: publicJwk,
        kid: "server-key-1",
      },
      true // isPublic = true
    );

    assert.ok(envelope);
    assert.ok(publicHeaders["X-PAYMENT-RESPONSE"]);

    const opened = await hpke.open({
      recipientPrivateJwk: privateJwk,
      envelope,
      expectedKid: "server-key-1",
      publicHeaders,
    });

    assert.equal(new TextDecoder().decode(opened.plaintext), JSON.stringify({}));
    assert.deepStrictEqual(opened.body, {});
  });
});

await test("createRequest helper", async (t) => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();
  const requestData = {
    action: "get_data",
    resource: "/api/users",
  };

  await t.test("creates a private request by default", async () => {
    const { envelope, publicHeaders } = await createRequest(
      hpke,
      {
        requestData,
        recipientPublicJwk: publicJwk,
        kid: "client-key-1",
      }
    );

    assert.ok(envelope);
    assert.strictEqual(publicHeaders, undefined);

    const opened = await hpke.open({
      recipientPrivateJwk: privateJwk,
      envelope,
      expectedKid: "client-key-1",
    });

    const decodedRequest = JSON.parse(new TextDecoder().decode(opened.plaintext));
    assert.deepStrictEqual(decodedRequest, requestData);
  });

  await t.test("creates a public request when isPublic is true", async () => {
    const { envelope, publicHeaders } = await createRequest(
      hpke,
      {
        requestData,
        recipientPublicJwk: publicJwk,
        kid: "client-key-1",
      },
      true // isPublic = true
    );

    assert.ok(envelope);
    // public headers are not emitted for generic request bodies; we may return a JSON body via direct seal
    assert.strictEqual(publicHeaders, undefined);

    const opened = await hpke.open({
      recipientPrivateJwk: privateJwk,
      envelope,
      expectedKid: "client-key-1",
    });

    const decodedRequest = JSON.parse(new TextDecoder().decode(opened.plaintext));
    assert.deepStrictEqual(decodedRequest, requestData);
  });

  await t.test("supports extensions parameter", async () => {
    // Register test-only custom header
    registerApprovedExtensionHeader("X-Custom");
    const extensions = [{ header: "X-Custom", payload: { custom: "value" } }];
    const { envelope } = await createRequest(
      hpke,
      {
        requestData,
        recipientPublicJwk: publicJwk,
        kid: "client-key-1",
        extensions,
      }
    );

    const opened = await hpke.open({
      recipientPrivateJwk: privateJwk,
      envelope,
      expectedKid: "client-key-1",
    });

    // Check headers include our extension
    const found = (opened.headers || []).find((h: any) => String(h.header).toLowerCase() === "x-custom".toLowerCase());
    assert.ok(found);
    assert.deepStrictEqual(found.value, { custom: "value" });
  });
});

await test("createResponse helper", async (t) => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();
  const responseData = {
    status: "success",
    data: { id: 123, name: "test" },
  };

  await t.test("creates a private response by default", async () => {
    const { envelope, publicHeaders } = await createResponse(
      hpke,
      {
        responseData,
        recipientPublicJwk: publicJwk,
        httpResponseCode: 200,
        kid: "server-key-1",
      }
    );

    assert.ok(envelope);
    assert.strictEqual(publicHeaders, undefined);

    const opened = await hpke.open({
      recipientPrivateJwk: privateJwk,
      envelope,
      expectedKid: "server-key-1",
    });

    assert.deepStrictEqual(JSON.parse(new TextDecoder().decode(opened.plaintext)), responseData);
    assert.deepStrictEqual(opened.body, responseData);
  });

  await t.test("creates a public response when isPublic is true", async () => {
    const { envelope, publicHeaders } = await createResponse(
      hpke,
      {
        responseData,
        recipientPublicJwk: publicJwk,
        httpResponseCode: 200,
        kid: "server-key-1",
      },
      true // isPublic = true
    );

    assert.ok(envelope);
    // For generic responses we do not emit headers; body exposure is controlled at direct seal level
    assert.strictEqual(publicHeaders, undefined);

    const opened = await hpke.open({
      recipientPrivateJwk: privateJwk,
      envelope,
      expectedKid: "server-key-1",
    });

    assert.deepStrictEqual(JSON.parse(new TextDecoder().decode(opened.plaintext)), responseData);
    assert.deepStrictEqual(opened.body, responseData);
  });
});