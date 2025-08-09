class X402Error(ValueError):
    pass


class InvalidEnvelope(X402Error):
    pass


class AeadMismatch(X402Error):
    pass


class AeadUnsupported(X402Error):
    pass


class KidMismatch(X402Error):
    pass


class EcdhLowOrder(X402Error):
    pass


class NsForbidden(X402Error):
    pass


class NsCollision(X402Error):
    pass


class AadMismatch(X402Error):
    pass


class PublicKeyNotInAad(X402Error):
    pass


class StreamKeyLen(X402Error):
    pass


class StreamNoncePrefixLen(X402Error):
    pass


class AeadLimit(X402Error):
    pass


class SeqNegative(X402Error):
    pass


class JwksHttpsRequired(X402Error):
    pass


class JwksHttpError(X402Error):
    pass


class JwksInvalid(X402Error):
    pass


class JwksKeyInvalid(X402Error):
    pass


class JwksKeyUseInvalid(X402Error):
    pass


class JwksKidInvalid(X402Error):
    pass


class JwksEmpty(X402Error):
    pass


class KidNotFound(X402Error):
    pass
