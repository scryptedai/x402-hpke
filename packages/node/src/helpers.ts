import { createHpke } from "./index.js";
import { OkpJwk } from "./keys.js";

/**
 * A helper to create a 402 Payment Required response.
 * @param hpke The configured hpke instance.
 * @param args The arguments for the payment required response.
 * @param isPublic If true, the entire response data is exposed in the public sidecar.
 * @returns The sealed envelope and an optional publicJsonBody.
 */
export async function createPaymentRequired(
  hpke: ReturnType<typeof createHpke>,
  args: {
    paymentRequiredData: Record<string, any>;
    recipientPublicJwk: OkpJwk;
    plaintext: Uint8Array;
    kid: string;
  },
  isPublic: boolean = false
) {
  return await hpke.seal({
    response: args.paymentRequiredData,
    httpResponseCode: 402,
    public: isPublic ? {
      makeEntitiesPublic: ["response"]
    } : undefined,
    recipientPublicJwk: args.recipientPublicJwk,
    plaintext: args.plaintext,
    kid: args.kid,
  });
}