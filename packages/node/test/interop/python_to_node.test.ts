import { test } from "node:test";
import assert from "node:assert/strict";
import { createHpke, generateKeyPair } from "../../src/index.js";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

await test("python seals -> node opens", async () => {
  const hpke = createHpke({ namespace: "myapp" });
  const { publicJwk, privateJwk } = await generateKeyPair();
  const x402 = {
    invoiceId: "inv_py",
    chainId: 8453,
    tokenContract: "0x" + "a".repeat(40),
    amount: "99",
    recipient: "0x" + "b".repeat(40),
    txHash: "0x" + "c".repeat(64),
    expiry: 9999999999,
    priceHash: "0x" + "d".repeat(64),
  };
  const payload = new TextEncoder().encode("from_python");
  const pyRoot = path.resolve(__dirname, "../../../python");
  const req = {
    namespace: "myapp",
    kid: "kidPY",
    recipient_public_jwk: publicJwk,
    plaintext_b64u: Buffer.from(payload).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_"),
    x402: { ...x402, replyToJwk: publicJwk },
  };
  const res = spawnSync("poetry", ["run", "python", "scripts/seal.py"], {
    cwd: pyRoot,
    input: JSON.stringify(req),
    encoding: "utf8",
  });
  assert.equal(res.status, 0, res.stderr);
  const envelope = JSON.parse(res.stdout);

  const opened = await hpke.open({ recipientPrivateJwk: privateJwk, envelope, expectedKid: "kidPY" });
  assert.equal(new TextDecoder().decode(opened.plaintext), "from_python");
  assert.equal(opened.x402.invoiceId, x402.invoiceId);
});