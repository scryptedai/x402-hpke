import fetch from "node-fetch";
import { createHpke, generateKeyPair } from "@x402-hpke/node";

(async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk } = await generateKeyPair();
  const x402 = {
    header: "X-Payment",
    payload: {
      invoiceId: "inv_client",
      chainId: 8453,
      tokenContract: "0x" + "a".repeat(40),
      amount: "1000",
      recipient: "0x" + "b".repeat(40),
      txHash: "0x" + "c".repeat(64),
      expiry: Math.floor(Date.now()/1000)+600,
      priceHash: "0x" + "d".repeat(64),
    }
  };
  const { envelope, publicHeaders } = await hpke.seal({ kid: "kid1", recipientPublicJwk: publicJwk, x402, public: { makeEntitiesPublic: ["X-PAYMENT"], as: "headers" } });
  await fetch("http://localhost:3000/fulfill", { method: "POST", headers: { "Content-Type": "application/json", ...(publicHeaders||{}) }, body: JSON.stringify(envelope) });
})();