import fetch from "node-fetch";
import { createHpke, generateKeyPair, createPayment } from "../../packages/node/dist/index.js";

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
  const PORT = Number(process.env.PORT || 43102);
  console.log("[client] sending to :%d", PORT);
  console.log("[client] publicHeaders:", publicHeaders);
  console.log("[client] envelope:", envelope);
  const resp = await fetch(`http://localhost:${PORT}/fulfill`, { method: "POST", headers: { "Content-Type": "application/json", ...(publicHeaders||{}) }, body: JSON.stringify(envelope) });
  console.log("[client] server response status:", resp.status);
  console.log("[client] server response body:", await resp.text());
})();