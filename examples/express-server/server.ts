import express from "express";
import bodyParser from "body-parser";
import { createHpke, generateKeyPair, createPayment } from "../../packages/node/dist/index.js";

const app = express();
const PORT = Number(process.env.PORT || 43102);
app.use(bodyParser.json({ limit: "1mb" }));

const hpke = createHpke({ namespace: "myapp" });
let serverKeys: any;
const ready = (async () => {
  serverKeys = await generateKeyPair();
})();

app.post("/quote", async (req, res) => {
  await ready;
  const { envelope, publicHeaders } = await createPayment(
    hpke,
    {
      paymentData: { invoiceId: "inv_demo" },
      recipientPublicJwk: serverKeys.publicJwk,
      kid: "kid1",
    },
    true
  );
  res
    .status(402)
    .set({ "Content-Type": "application/x402-envelope+json", "Cache-Control": "no-store", ...(publicHeaders ?? {}) })
    .send(envelope);
});

app.post("/fulfill", async (req, res) => {
  await ready;
  const env = req.body;
  try {
    const sidecar: Record<string, string> = pickSidecarFrom(req.headers);
    console.log("[server] received envelope typ=%s kid=%s", env?.typ, env?.kid);
    console.log("[server] sidecar headers:", sidecar);
    const opened = await hpke.open({ recipientPrivateJwk: serverKeys.privateJwk, envelope: env, expectedKid: env.kid, publicHeaders: sidecar });
    console.log("[server] decrypted plaintext:", new TextDecoder().decode(opened.plaintext));
    console.log("[server] opened.body:", opened.body);
    console.log("[server] opened.headers:", opened.headers);
    res.json({ ok: true });
  } catch (e: any) {
    console.error("[server] error:", e?.message || e);
    res.status(400).json({ error: e.message });
  }
});

app.get("/pub", async (_req, res) => {
  await ready;
  res.json(serverKeys.publicJwk);
});

app.listen(PORT, () => console.log(`Express example on :${PORT}`));

function pickSidecarFrom(headers: any): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of Object.keys(headers)) {
    const kl = k.toLowerCase();
    if (kl === "x-payment") out["X-PAYMENT"] = String(headers[k]);
    if (kl === "x-payment-response") out["X-PAYMENT-RESPONSE"] = String(headers[k]);
    if (kl === "x-x402-invoice-id") out["X-X402-Invoice-Id"] = String(headers[k]);
    if (kl === "x-x402-expiry") out["X-X402-Expiry"] = String(headers[k]);
    if (kl === "x-myapp-trace-id") out["X-myapp-Trace-Id"] = String(headers[k]);
  }
  return out;
}