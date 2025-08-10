import { createHpke, generateKeyPair, createPayment } from "../src/index.js";

async function debug() {
  try {
    const hpke = createHpke({ namespace: "myapp" });
    const { publicJwk, privateJwk } = await generateKeyPair();
    const paymentData = {
      invoiceId: "inv_123",
    };

    console.log("Testing createPayment...");
    const result = await createPayment(
      hpke,
      {
        paymentData,
        recipientPublicJwk: publicJwk,
        kid: "server-key-1",
      },
      true // isPublic = true
    );

    console.log("Result:", JSON.stringify(result, null, 2));
    console.log("Result type:", typeof result);
    console.log("Result keys:", Object.keys(result || {}));
  } catch (error) {
    console.error("Error:", error);
  }
}

debug(); 