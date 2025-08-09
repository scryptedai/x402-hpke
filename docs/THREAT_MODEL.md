# Threat Model

This document outlines the security goals, non-goals, attacker model, and mitigations for x402-hpke.

## Security Goals

### 1. Confidentiality
- **Payload protection**: Encrypted payloads cannot be read without the private key
- **Metadata binding**: All metadata is cryptographically bound to the payload
- **Forward secrecy**: Compromise of long-term keys doesn't reveal past communications

### 2. Integrity
- **AAD protection**: Associated data cannot be modified without detection
- **Sidecar validation**: Public sidecars must match AAD reconstruction
- **Envelope integrity**: Envelope structure cannot be tampered with

### 3. Authenticity
- **Sender authentication**: Recipients can verify the sender's identity
- **Key binding**: Public keys are cryptographically bound to the namespace
- **Non-repudiation**: Senders cannot deny sending encrypted messages

## Non-Goals

### 1. Anonymity
- **No anonymity**: Sender and recipient identities are visible in headers
- **No privacy**: Metadata structure and keys are observable
- **No deniability**: Cryptographic proof of communication exists

### 2. Availability
- **No DDoS protection**: Library doesn't protect against denial of service
- **No rate limiting**: Application-level rate limiting must be implemented separately
- **No load balancing**: No built-in load distribution mechanisms

### 3. Key Management
- **No key escrow**: Library doesn't provide key backup or recovery
- **No key rotation**: Applications must implement their own rotation strategies
- **No key validation**: No built-in validation of key strength or parameters

## Attacker Model

### 1. Network Attacker
**Capabilities**:
- Read, modify, inject, or drop network traffic
- Observe all HTTP headers and metadata
- Perform man-in-the-middle attacks
- Replay captured messages

**Limitations**:
- Cannot break cryptographic primitives
- Cannot access private keys
- Cannot forge valid signatures

### 2. Application Attacker
**Capabilities**:
- Control application code and configuration
- Access application memory and storage
- Modify application behavior
- Access application logs

**Limitations**:
- Cannot access other applications' memory
- Cannot break operating system isolation
- Cannot access hardware security modules

### 3. Cryptographic Attacker
**Capabilities**:
- Perform cryptanalysis on ciphertexts
- Attempt to break key derivation
- Analyze side-channel information
- Perform timing attacks

**Limitations**:
- Cannot break standard cryptographic assumptions
- Cannot access implementation internals
- Cannot perform quantum attacks (assumes classical computing)

## Mitigations

### 1. Cryptographic Security

#### HPKE Security
- **X25519**: Elliptic curve Diffie-Hellman with 128-bit security
- **HKDF-SHA256**: Key derivation with 256-bit security
- **ChaCha20-Poly1305**: AEAD with 128-bit security
- **Nonce uniqueness**: Each encryption uses a unique nonce

#### Key Management
- **HTTPS only**: JWKS endpoints require secure transport
- **Key rotation**: Support for regular key updates
- **Key validation**: Verification of key format and parameters

### 2. Sidecar Security

#### AAD Binding
- **Cryptographic binding**: All metadata bound to ciphertext
- **Canonicalization**: Deterministic byte representation
- **Validation**: Sidecar must match AAD reconstruction

#### Header Security
- **Case-insensitive**: Header names normalized during processing
- **Whitespace handling**: Proper OWS trimming and validation
- **Extension validation**: Only approved extensions allowed

### 3. Implementation Security

#### Memory Safety
- **Zero-copy**: Minimize unnecessary memory allocations
- **Secure comparison**: Constant-time equality checks
- **Buffer validation**: Proper bounds checking on all inputs

#### Error Handling
- **Fail closed**: Cryptographic failures result in errors
- **No information leakage**: Error messages don't reveal secrets
- **Graceful degradation**: Handle errors without compromising security

## Attack Vectors and Mitigations

### 1. Replay Attacks

**Attack**: Attacker replays captured encrypted messages
**Mitigation**: 
- Include unique identifiers in AAD (e.g., `requestId`, `nonce`)
- Implement application-level deduplication
- Use short-lived keys for high-risk contexts

**Example**:
```typescript
const x402 = {
  header: "X-Payment",
  payload: {
    requestId: crypto.randomUUID(),
    timestamp: Date.now(),
    // ... other payment details
  }
};
```

### 2. Sidecar Manipulation

**Attack**: Attacker modifies public headers to bypass validation
**Mitigation**:
- Server rebuilds AAD from sidecar
- Requires byte-for-byte equality
- Mismatch results in `400 AAD_MISMATCH`

**Example**:
```typescript
// Server-side validation
const reconstructedAad = buildAadFromSidecar(publicHeaders);
if (!timingSafeEqual(reconstructedAad, envelope.aad)) {
  throw new Error('AAD_MISMATCH');
}
```

### 3. Key Confusion

**Attack**: Attacker uses wrong key for encryption/decryption
**Mitigation**:
- `kid` field uniquely identifies keys
- JWKS validation ensures key format
- Namespace binding prevents cross-application attacks

**Example**:
```typescript
// Verify key belongs to expected namespace
if (jwk.kty !== 'OKP' || jwk.crv !== 'X25519') {
  throw new Error('INVALID_KEY_TYPE');
}
```

### 4. Timing Attacks

**Attack**: Attacker uses timing differences to extract secrets
**Mitigation**:
- Constant-time comparisons for sensitive operations
- No early returns in cryptographic code
- Consistent error handling paths

**Example**:
```typescript
// Use constant-time comparison
import { timingSafeEqual } from 'crypto';

if (!timingSafeEqual(aad1, aad2)) {
  throw new Error('AAD_MISMATCH');
}
```

## Security Recommendations

### 1. Application Design

- **Unique identifiers**: Include nonces or request IDs in AAD
- **Key rotation**: Implement regular key rotation schedules
- **Monitoring**: Log and monitor for suspicious activity
- **Rate limiting**: Implement application-level rate limiting

### 2. Key Management

- **Secure generation**: Use cryptographically secure random number generators
- **Key storage**: Store private keys securely (HSM, key management service)
- **Access control**: Limit access to private keys
- **Audit logging**: Log all key operations

### 3. Deployment

- **HTTPS only**: Never use HTTP for JWKS endpoints
- **Security headers**: Implement proper security headers
- **Network security**: Use firewalls and network segmentation
- **Monitoring**: Monitor for network attacks and anomalies

### 4. Testing

- **Security testing**: Regular penetration testing
- **Fuzzing**: Test with malformed inputs
- **Side-channel analysis**: Test for timing and power analysis vulnerabilities
- **Interop testing**: Test with other implementations

## Compliance and Standards

### 1. Cryptographic Standards

- **RFC 9180**: HPKE standard compliance
- **RFC 7517**: JWKS format compliance
- **RFC 7518**: JWA algorithm compliance
- **NIST SP 800-56A**: Key agreement compliance

### 2. Security Standards

- **OWASP**: Follow OWASP security guidelines
- **CWE**: Address common weakness enumerations
- **CVE**: Monitor for security vulnerabilities
- **Security advisories**: Subscribe to security mailing lists

## Future Considerations

### 1. Post-Quantum Security

- **Quantum resistance**: Consider post-quantum algorithms
- **Hybrid schemes**: Combine classical and post-quantum cryptography
- **Migration planning**: Plan for algorithm transitions

### 2. Advanced Threats

- **Supply chain attacks**: Protect against compromised dependencies
- **Side-channel attacks**: Advanced timing and power analysis
- **Quantum computers**: Prepare for quantum computing threats

### 3. Compliance Evolution

- **Regulatory changes**: Monitor for new compliance requirements
- **Industry standards**: Follow evolving industry best practices
- **Security research**: Stay current with security research