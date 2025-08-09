# JWKS (JSON Web Key Set)

JWKS utilities provide secure key management and rotation capabilities for x402-hpke implementations.

## Security Requirements

- **HTTPS only**: All JWKS endpoints must use HTTPS
- **Caching**: Respect Cache-Control and Expires headers for performance
- **Key selection**: Use `kid` (Key ID) for unambiguous key selection
- **Rotation**: Support key rotation without service interruption

## Node.js Implementation

```typescript
import { fetchJwks, setJwks, selectJwkFromJwks } from "@x402-hpke/node";

// Fetch JWKS from remote endpoint
const jwks = await fetchJwks("https://example.com/.well-known/jwks.json");

// Set JWKS for a specific URL (useful for testing or local development)
setJwks("https://example.com/.well-known/jwks.json", jwks);

// Select a specific key by kid
const jwk = selectJwkFromJwks(jwks, "kid1");
if (!jwk) {
  throw new Error("Key not found");
}
```

## Python Implementation

```python
from x402_hpke import fetch_jwks, set_jwks, select_jwk

# Fetch JWKS from remote endpoint
jwks = fetch_jwks("https://example.com/.well-known/jwks.json")

# Set JWKS for a specific URL (useful for testing or local development)
set_jwks("https://example.com/.well-known/jwks.json", jwks)

# Select a specific key by kid
jwk = select_jwk("kid1", jwks, "https://example.com/.well-known/jwks.json")
if not jwk:
    raise ValueError("Key not found")
```

## JWKS Structure

The JWKS follows RFC 7517 format:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "X25519",
      "x": "base64url-encoded-public-key",
      "kid": "unique-key-identifier",
      "use": "enc",
      "alg": "ECDH-ES"
    }
  ]
}
```

### Required Fields

- **kty**: Key type (must be "OKP" for X25519)
- **crv**: Curve (must be "X25519")
- **x**: Base64url-encoded public key (32 bytes)
- **kid**: Unique key identifier

### Optional Fields

- **use**: Key usage ("enc" for encryption)
- **alg**: Algorithm ("ECDH-ES" for ECDH key agreement)
- **exp**: Expiration timestamp
- **nbf**: Not-before timestamp

## Caching Behavior

The library implements intelligent caching:

- **Cache-Control**: Respects `max-age` directive
- **Expires**: Falls back to Expires header if Cache-Control not present
- **Default TTL**: 5 minutes if no caching headers provided
- **Background refresh**: Automatically refreshes expired keys

## Key Rotation Strategy

### 1. Rolling Rotation

```typescript
// Add new key to JWKS
const newJwks = {
  keys: [
    ...existingKeys,
    {
      kty: "OKP",
      crv: "X25519", 
      x: newPublicKey,
      kid: "kid2",
      use: "enc",
      alg: "ECDH-ES"
    }
  ]
};

// Update JWKS endpoint
await updateJwksEndpoint(newJwks);
```

### 2. Graceful Deprecation

```typescript
// Mark old key as deprecated
const deprecatedJwks = {
  keys: existingKeys.map(key => 
    key.kid === "kid1" 
      ? { ...key, exp: Math.floor(Date.now() / 1000) + 86400 } // 24 hours
      : key
  )
};
```

## Error Handling

```typescript
try {
  const jwks = await fetchJwks(url);
  const jwk = selectJwkFromJwks(jwks, kid);
  
  if (!jwk) {
    throw new Error(`Key ${kid} not found in JWKS`);
  }
  
  return jwk;
} catch (error) {
  if (error.code === 'ENOTFOUND') {
    // Network error - retry with exponential backoff
    throw new Error(`Failed to fetch JWKS: ${error.message}`);
  }
  
  if (error.code === 'INVALID_JWKS') {
    // Invalid JWKS format
    throw new Error(`Invalid JWKS format: ${error.message}`);
  }
  
  throw error;
}
```

## Best Practices

### 1. Key Management

- Use unique `kid` values for each key
- Implement proper key rotation schedules
- Monitor key expiration and usage
- Use secure key generation (cryptographically random)

### 2. Performance

- Implement proper caching headers on JWKS endpoints
- Use CDN for global distribution
- Consider implementing stale-while-revalidate caching
- Monitor JWKS fetch performance

### 3. Security

- Always use HTTPS for JWKS endpoints
- Implement proper access controls
- Monitor for unauthorized access attempts
- Use short-lived keys when possible

## Testing

```typescript
// Mock JWKS for testing
const mockJwks = {
  keys: [
    {
      kty: "OKP",
      crv: "X25519",
      x: "base64url-encoded-test-key",
      kid: "test-kid",
      use: "enc",
      alg: "ECDH-ES"
    }
  ]
};

setJwks("https://test.example.com/.well-known/jwks.json", mockJwks);
```

## Integration with HPKE

```typescript
import { createHpke, fetchJwks, selectJwkFromJwks } from "@x402-hpke/node";

const hpke = createHpke({ namespace: "myapp" });

// Fetch recipient's public key
const jwks = await fetchJwks("https://recipient.com/.well-known/jwks.json");
const recipientJwk = selectJwkFromJwks(jwks, "recipient-kid");

// Seal with recipient's public key
const { envelope, publicHeaders } = await hpke.seal({
  kid: "sender-kid",
  recipientPublicJwk: recipientJwk,
  plaintext: Buffer.from("hello"),
  x402: { header: "X-Payment", payload: { /* payment details */ } }
});
```