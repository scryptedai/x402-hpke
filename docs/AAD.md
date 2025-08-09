# AAD (Additional Authenticated Data) Rules

- JSON canonicalization with sorted keys and compact separators.
- Normalize hex to lowercase, ensure 0x prefix where specified.
- `amount` is a base-10 uint256 string, no leading zeros (except "0").
- Integers only for numeric fields.
- AAD bytes = utf-8 bytes of the string "<ns>|v1|" + json(x402) + "|" + json(app?).

Reply-to (required)
- A request MUST contain reply-to information so a recipient can encrypt the response:
  - Either: `replyToJwks` (HTTPS URL) and `replyToKid`, or
  - `replyToJwk` (X25519 OKP public key).
- `replyTo*` fields are part of AAD and MUST NOT be mirrored in sidecar.

Public reply opt-in (optional)
- `replyPublicOk: true` in AAD allows the recipient to respond without an envelope (plaintext), if they choose.
- When omitted or false, recipients MUST reply with an envelope using the supplied reply-to.

Encoding (normative)
- JSON canonicalization: UTF-8; keys sorted lexicographically; compact separators (no spaces).
- Base64url without padding for envelope fields `enc`, `aad`, and `ct`.

Validation
- `invoiceId`: non-empty string
- `chainId`: integer
- `tokenContract`: 0x-prefixed, lowercase hex, 40 nibbles
- `amount`: base-10 uint string (no leading zeros unless "0")
- `recipient`: 0x-prefixed, lowercase hex, 40 nibbles
- `txHash`: 0x-prefixed, lowercase hex, 64 nibbles
- `expiry`: integer (unix seconds)
- `priceHash`: 0x-prefixed, lowercase hex, 64 nibbles