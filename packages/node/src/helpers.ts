import { createHpke } from "./index.js";
import { OkpJwk } from "./keys.js";
import { X402Extension } from "./extensions.js";
import { x402SecureTransport, CanonicalHeaders } from "./index.js";

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
  const transport = new x402SecureTransport("PAYMENT_REQUIRED", args.paymentRequiredData);
  const result = await hpke.seal({
    transport,
    makeEntitiesPublic: isPublic ? "all" : undefined,
    recipientPublicJwk: args.recipientPublicJwk,
    kid: args.kid,
  } as any);

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
  const header = { header: CanonicalHeaders.X_PAYMENT, value: { payload: args.paymentData } };
  const extensions = (args.extensions || []).map((e) => ({ header: e.header, value: e.payload }));
  const transport = new x402SecureTransport("PAYMENT", header.value, undefined, extensions);
  const result = await hpke.seal({
    transport,
    makeEntitiesPublic: isPublic ? [CanonicalHeaders.X_PAYMENT] : undefined,
    recipientPublicJwk: args.recipientPublicJwk,
    kid: args.kid,
  } as any);

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
  const header = { header: CanonicalHeaders.X_PAYMENT_RESPONSE, value: args.settlementData };
  const extensions = (args.extensions || []).map((e) => ({ header: e.header, value: e.payload }));
  const transport = new x402SecureTransport("PAYMENT_RESPONSE", header.value, 200, extensions);
  const result = await hpke.seal({
    transport,
    makeEntitiesPublic: isPublic ? [CanonicalHeaders.X_PAYMENT_RESPONSE] : undefined,
    recipientPublicJwk: args.recipientPublicJwk,
    kid: args.kid,
  } as any);

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
  const transport = new x402SecureTransport("OTHER_REQUEST", args.requestData, undefined, (args.extensions || []).map((e) => ({ header: e.header, value: e.payload })));
  const result = await hpke.seal({
    transport,
    makeEntitiesPublic: isPublic ? "all" : undefined,
    recipientPublicJwk: args.recipientPublicJwk,
    kid: args.kid,
  } as any);

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
  const transport = new x402SecureTransport("OTHER_RESPONSE", args.responseData, args.httpResponseCode, (args.extensions || []).map((e) => ({ header: e.header, value: e.payload })));
  const result = await hpke.seal({
    transport,
    makeEntitiesPublic: isPublic ? "all" : undefined,
    recipientPublicJwk: args.recipientPublicJwk,
    kid: args.kid,
  } as any);

  return {
    envelope: result.envelope,
    publicHeaders: result.publicHeaders,
  };
}