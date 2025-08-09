# AAD Rules

- JSON canonicalization with sorted keys and compact separators.
- Normalize hex to lowercase, ensure 0x prefix where specified.
- `amount` is a base-10 uint256 string, no leading zeros (except "0").
- Integers only for numeric fields.
- AAD bytes = utf8("<ns>|v1|" + json(x402) + "|" + json(app?)).