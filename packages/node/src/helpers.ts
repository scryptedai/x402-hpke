import { createHpke } from "./index.js";
import { OkpJwk } from "./keys.js";
import { X402Extension } from "./extensions.js";

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
    kid: string;
  },
  isPublic: boolean = false
) {
  const result = await hpke.seal({
    response: args.paymentRequiredData,
    httpResponseCode: 402,
    public: isPublic
      ? {
          makeEntitiesPublic: ["response"],
        }
      : undefined,
    recipientPublicJwk: args.recipientPublicJwk,
    kid: args.kid,
  });

  return {
    envelope: result.envelope,
    publicJsonBody: result.publicJsonBody,
  };
}

/**
 * A helper to create a client-side X-Payment request.
 * @param hpke The configured hpke instance.
 * @param args The arguments for the payment request.
 * @param isPublic If true, exposes the payment data in a public X-Payment header.
 * @returns The sealed envelope and an optional publicHeaders sidecar.
 */
export async function createPayment(
  hpke: ReturnType<typeof createHpke>,
  args: {
    paymentData: Record<string, any>;
    recipientPublicJwk: OkpJwk;
    kid: string;
    extensions?: X402Extension[];
  },
  isPublic: boolean = false
) {
  const result = await hpke.seal({
    x402: {
      header: "X-Payment",
      payload: args.paymentData,
    },
    public: isPublic ? {
      makeEntitiesPublic: ["X-PAYMENT"]
    } : undefined,
    recipientPublicJwk: args.recipientPublicJwk,
    kid: args.kid,
    extensions: args.extensions,
  });

  return {
    envelope: result.envelope,
    publicHeaders: result.publicHeaders,
  };
}

/**
 * A helper to create a server-side X-Payment-Response.
 * @param hpke The configured hpke instance.
 * @param args The arguments for the payment response.
 * @param isPublic If true, exposes the settlement data in a public X-Payment-Response header.
 * @returns The sealed envelope and an optional publicHeaders sidecar.
 */
export async function createPaymentResponse(
  hpke: ReturnType<typeof createHpke>,
  args: {
    settlementData: Record<string, any>;
    recipientPublicJwk: OkpJwk;
    kid: string;
    extensions?: X402Extension[];
  },
  isPublic: boolean = false
) {
  const result = await hpke.seal({
    x402: {
      header: "X-Payment-Response",
      payload: args.settlementData,
    },
    httpResponseCode: 200,
    public: isPublic ? {
      makeEntitiesPublic: ["X-PAYMENT-RESPONSE"]
    } : undefined,
    recipientPublicJwk: args.recipientPublicJwk,
    kid: args.kid,
    extensions: args.extensions,
  });

  return {
    envelope: result.envelope,
    publicHeaders: result.publicHeaders,
  };
}

/**
 * A helper to create a general-purpose request envelope.
 * @param hpke The configured hpke instance.
 * @param args The arguments for the request.
 * @param isPublic If true, exposes the request data in a public header.
 * @returns The sealed envelope and an optional publicHeaders sidecar.
 */
export async function createRequest(
  hpke: ReturnType<typeof createHpke>,
  args: {
    requestData: Record<string, any>;
    recipientPublicJwk: OkpJwk;
    kid: string;
    extensions?: X402Extension[];
  },
  isPublic: boolean = false
) {
  const result = await hpke.seal({
    request: args.requestData,
    public: isPublic ? {
      makeEntitiesPublic: ["request"]
    } : undefined,
    recipientPublicJwk: args.recipientPublicJwk,
    kid: args.kid,
    extensions: args.extensions,
  });

  return {
    envelope: result.envelope,
    publicHeaders: result.publicHeaders,
  };
}

/**
 * A helper to create a general-purpose response envelope.
 * @param hpke The configured hpke instance.
 * @param args The arguments for the response.
 * @param isPublic If true, exposes the response data in a public header.
 * @returns The sealed envelope and an optional publicHeaders sidecar.
 */
export async function createResponse(
  hpke: ReturnType<typeof createHpke>,
  args: {
    responseData: Record<string, any>;
    recipientPublicJwk: OkpJwk;
    httpResponseCode: number;
    kid: string;
    extensions?: X402Extension[];
  },
  isPublic: boolean = false
) {
  const result = await hpke.seal({
    response: args.responseData,
    httpResponseCode: args.httpResponseCode,
    public: isPublic ? {
      makeEntitiesPublic: ["response"]
    } : undefined,
    recipientPublicJwk: args.recipientPublicJwk,
    kid: args.kid,
    extensions: args.extensions,
  });

  return {
    envelope: result.envelope,
    publicHeaders: result.publicHeaders,
  };
}