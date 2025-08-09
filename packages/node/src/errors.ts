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
 