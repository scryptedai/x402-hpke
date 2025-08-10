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
  const requestPayload = { action: "from_python" };
  const pyRoot = path.resolve(__dirname, "../../../python");
  const req = {
    namespace: "myapp",
    kid: "kidPY",
    recipient_public_jwk: publicJwk,
    request: requestPayload,
  } as any;
  const res = spawnSync("poetry", ["run", "python", "scripts/seal.py"], {
    cwd: pyRoot,
    input: JSON.stringify(req),
    encoding: "utf8",
  });
  assert.equal(res.status, 0, res.stderr);
  const envelope = JSON.parse(res.stdout);

  const opened = await hpke.open({ recipientPrivateJwk: privateJwk, envelope, expectedKid: "kidPY" });
  assert.equal(new TextDecoder().decode(opened.plaintext), JSON.stringify(requestPayload));
  assert.deepStrictEqual(opened.body, requestPayload);
});