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
    invoiceId: "inv_demo",
    chainId: 8453,
    tokenContract: "0x" + "a".repeat(40),
    amount: "1000",
    recipient: "0x" + "b".repeat(40),
    txHash: "0x" + "c".repeat(64),
    expiry: Math.floor(Date.now() / 1000) + 600,
    priceHash: "0x" + "d".repeat(64),
  };
  const payload = new TextEncoder().encode(JSON.stringify({ type: "quote" }));
  const { envelope } = await hpke.seal({ kid: "kid1", recipientPublicJwk: serverKeys.publicJwk, plaintext: payload, x402 });
  res.status(402).set({ "Content-Type": "application/myapp+hpke", "Cache-Control": "no-store" }).send(envelope);
});

app.post("/fulfill", async (req, res) => {
  const env = req.body;
  try {
    const opened = await hpke.open({ recipientPrivateJwk: serverKeys.privateJwk, envelope: env, expectedKid: env.kid });
    // TODO: verify facilitator using opened.x402
    res.json({ ok: true });
  } catch (e: any) {
    res.status(400).json({ error: e.message });
  }
});

app.listen(3000, () => console.log("Express example on :3000"));