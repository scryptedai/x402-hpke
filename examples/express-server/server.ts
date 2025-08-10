import express from "express";
import bodyParser from "body-parser";
import { createHpke, generateKeyPair } from "@x402-hpke/node";

const app = express();
app.use(bodyParser.json({ limit: "1mb" }));

const hpke = createHpke({ namespace: "myapp" });
let serverKeys: any;

(async () => {
  serverKeys = await generateKeyPair();
})();

app.post("/quote", async (req, res) => {
  const x402 = {
    header: "X-Payment",
    payload: {
      invoiceId: "inv_demo",
      chainId: 8453,
      tokenContract: "0x" + "a".repeat(40),
      amount: "1000",
      recipient: "0x" + "b".repeat(40),
      txHash: "0x" + "c".repeat(64),
      expiry: Math.floor(Date.now() / 1000) + 600,
      priceHash: "0x" + "d".repeat(64),
    }
  };
  const { envelope, publicHeaders } = await hpke.seal({
    kid: "kid1",
    recipientPublicJwk: serverKeys.publicJwk,
    x402,
    public: { makeEntitiesPublic: ["X-PAYMENT"], as: "headers" },
  });
  res
    .status(402)
    .set({ "Content-Type": "application/x402-envelope+json", "Cache-Control": "no-store", ...(publicHeaders ?? {}) })
    .send(envelope);
});

app.post("/fulfill", async (req, res) => {
  const env = req.body;
  try {
    const sidecar: Record<string, string> = pickSidecarFrom(req.headers);
    const opened = await hpke.open({ recipientPrivateJwk: serverKeys.privateJwk, envelope: env, expectedKid: env.kid, publicHeaders: sidecar });
    res.json({ ok: true });
  } catch (e: any) {
    res.status(400).json({ error: e.message });
  }
});

app.listen(3000, () => console.log("Express example on :3000"));

function pickSidecarFrom(headers: any): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase() === "x-x402-invoice-id") out["X-X402-Invoice-Id"] = String(headers[k]);
    if (k.toLowerCase() === "x-x402-expiry") out["X-X402-Expiry"] = String(headers[k]);
    if (k.toLowerCase() === "x-myapp-trace-id") out["X-myapp-Trace-Id"] = String(headers[k]);
  }
  return out;
}