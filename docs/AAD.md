# AAD Rules

- JSON canonicalization with sorted keys and compact separators.
- Normalize hex to lowercase, ensure 0x prefix where specified.
- `amount` is a base-10 uint256 string, no leading zeros (except "0").
- Integers only for numeric fields.
- AAD bytes = utf8("<ns>|v1|" + json(x402) + "|" + json(app?)).

Validation
- `invoiceId`: non-empty string
- `chainId`: integer
- `tokenContract`: 0x-prefixed, lowercase hex, 40 nibbles
- `amount`: base-10 uint string (no leading zeros unless "0")
- `recipient`: 0x-prefixed, lowercase hex, 40 nibbles
- `txHash`: 0x-prefixed, lowercase hex, 64 nibbles
- `expiry`: integer (unix seconds)
- `priceHash`: 0x-prefixed, lowercase hex, 64 nibbles