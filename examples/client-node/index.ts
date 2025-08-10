import fetch from "node-fetch";
import { createHpke, generateKeyPair, createPayment } from "@x402-hpke/node";

(async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk } = await generateKeyPair();
  const { envelope, publicHeaders } = await createPayment(
    hpke,
    {
      paymentData: { invoiceId: "inv_client" },
      recipientPublicJwk: publicJwk,
      kid: "kid1",
    },
    true // expose X-PAYMENT header publicly (optional)
  );
  await fetch("http://localhost:3000/fulfill", { method: "POST", headers: { "Content-Type": "application/json", ...(publicHeaders||{}) }, body: JSON.stringify(envelope) });
})();