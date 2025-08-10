export class X402Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

export class InvalidEnvelopeError extends X402Error {}
export class AeadMismatchError extends X402Error {}
export class AeadUnsupportedError extends X402Error {}
export class KidMismatchError extends X402Error {}
export class EcdhLowOrderError extends X402Error {}
export class NsForbiddenError extends X402Error {}
export class NsCollisionError extends X402Error {}
export class AadMismatchError extends X402Error {}
export class PublicKeyNotInAadError extends X402Error {}
export class AeadLimitError extends X402Error {}
export class StreamNoncePrefixLenError extends X402Error {}
export class ReplyToMissingError extends X402Error {}
export class ReplyToSidecarForbiddenError extends X402Error {}
export class ReplyToFormatError extends X402Error {}
export class ReplyToConflictError extends X402Error {}
export class Invalid402HeaderError extends X402Error {}
export class InvalidPaymentResponseError extends X402Error {}
export class InvalidPaymentRequestError extends X402Error {}
export class X402HeaderError extends X402Error {}
export class X402PayloadError extends X402Error {}
export class X402ExtensionUnapprovedError extends X402Error {}
export class X402ExtensionDuplicateError extends X402Error {}
export class X402ExtensionPayloadError extends X402Error {}
export class JwksHttpsRequiredError extends X402Error {}
export class JwksHttpError extends X402Error {}
export class JwksInvalidError extends X402Error {}
export class JwksKeyInvalidError extends X402Error {}
export class JwksKeyUseInvalidError extends X402Error {}
export class JwksKidInvalidError extends X402Error {}
export class X402RequiredError extends X402Error {}
export class JwksUrlRequiredError extends X402Error {}
 