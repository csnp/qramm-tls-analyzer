# Policy-Based Scanning Guide

QRAMM TLS Analyzer supports policy-as-code for automated compliance checking. This guide explains how to use built-in policies and create custom ones.

## Built-in Policies

### List Available Policies

```bash
tlsanalyzer policies
```

Output:
```
Available Security Policies:
─────────────────────────────────────────────────────────

  modern
    Modern TLS configuration for 2024+

  strict
    Strict TLS configuration with TLS 1.3 required

  cnsa-2.0-2027
    CNSA 2.0 compliance target for 2027 - new NSS systems

  cnsa-2.0-2030
    CNSA 2.0 compliance target for 2030 - TLS 1.3 required

  cnsa-2.0-2035
    CNSA 2.0 compliance target for 2035 - full PQC
```

### Policy Descriptions

| Policy | Use Case |
|--------|----------|
| `modern` | General-purpose secure configuration for web applications |
| `strict` | High-security environments requiring TLS 1.3 only |
| `cnsa-2.0-2027` | Government/defense systems needing CNSA 2.0 by 2027 |
| `cnsa-2.0-2030` | Systems targeting 2030 compliance deadline |
| `cnsa-2.0-2035` | Full post-quantum transition planning |

## Using Built-in Policies

```bash
# Evaluate against a policy
tlsanalyzer example.com --policy modern

# Multiple formats
tlsanalyzer example.com --policy cnsa-2.0-2027 --format json
tlsanalyzer example.com --policy strict --format html -o report.html
```

## Custom Policies

Create custom policies in YAML format to match your organization's requirements.

### Basic Structure

```yaml
name: my-organization-policy
version: "1.0"
description: Custom security policy for my organization
extends: modern  # Optional: inherit from built-in policy

rules:
  protocol:
    # Protocol version requirements
  cipher:
    # Cipher suite requirements
  certificate:
    # Certificate requirements
  quantum:
    # Quantum readiness requirements
```

### Protocol Rules

```yaml
rules:
  protocol:
    # Minimum acceptable TLS version
    minVersion: TLS 1.2

    # Versions that MUST be supported
    requiredVersions:
      - TLS 1.3

    # Versions that MUST NOT be supported
    bannedVersions:
      - SSL 3.0
      - TLS 1.0
      - TLS 1.1
```

### Cipher Rules

```yaml
rules:
  cipher:
    # Minimum symmetric key size in bits
    minKeySize: 128

    # Require forward secrecy (ephemeral key exchange)
    requireForwardSecrecy: true

    # Algorithms that MUST NOT be used
    bannedAlgorithms:
      - 3DES
      - RC4
      - MD5
      - SHA1
      - DES
      - EXPORT

    # Specific cipher suites to ban
    bannedCipherSuites:
      - TLS_RSA_WITH_AES_128_CBC_SHA
      - TLS_RSA_WITH_AES_256_CBC_SHA

    # Cipher suites that SHOULD be preferred
    preferredCipherSuites:
      - TLS_AES_256_GCM_SHA384
      - TLS_CHACHA20_POLY1305_SHA256
```

### Certificate Rules

```yaml
rules:
  certificate:
    # Minimum days until expiry
    minValidityDays: 30

    # Maximum certificate lifetime in days
    maxValidityDays: 397

    # Minimum RSA key size in bits
    minRsaKeySize: 2048

    # Minimum ECC key size in bits
    minEccKeySize: 256

    # Signature algorithms to ban
    bannedSignatureAlgorithms:
      - SHA1
      - MD5
      - MD2

    # Allow self-signed certificates
    allowSelfSigned: false

    # Require certificate transparency
    requireCT: true
```

### Quantum Rules

```yaml
rules:
  quantum:
    # Require hybrid PQC key exchange
    requireHybridKeyExchange: true

    # Require full PQC (no classical fallback)
    requireFullPqc: false

    # Minimum quantum readiness score (0-100)
    minQuantumScore: 50

    # Target year for CNSA 2.0 compliance
    cnsa2TargetYear: 2027

    # Required key exchange algorithms
    requiredKeyExchangeAlgorithms:
      - ML-KEM-768
      - ML-KEM-1024
      - X25519MLKEM768

    # Required signature algorithms
    requiredSignatureAlgorithms:
      - ML-DSA-65
      - ML-DSA-87
```

## Complete Example

```yaml
# financial-services-policy.yaml
name: financial-services-policy
version: "2.0"
description: Secure TLS policy for financial services with PQC readiness

rules:
  protocol:
    minVersion: TLS 1.2
    requiredVersions:
      - TLS 1.3
    bannedVersions:
      - SSL 2.0
      - SSL 3.0
      - TLS 1.0
      - TLS 1.1

  cipher:
    minKeySize: 256
    requireForwardSecrecy: true
    bannedAlgorithms:
      - 3DES
      - RC4
      - MD5
      - SHA1
      - DES
      - EXPORT
      - NULL
      - ANON
    preferredCipherSuites:
      - TLS_AES_256_GCM_SHA384
      - TLS_CHACHA20_POLY1305_SHA256
      - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
      - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

  certificate:
    minValidityDays: 30
    maxValidityDays: 397
    minRsaKeySize: 3072
    minEccKeySize: 384
    bannedSignatureAlgorithms:
      - SHA1
      - MD5
    allowSelfSigned: false
    requireCT: true

  quantum:
    requireHybridKeyExchange: false
    minQuantumScore: 25
    cnsa2TargetYear: 2027
```

## Using Custom Policies

```bash
# Apply custom policy
tlsanalyzer example.com --policy-file financial-services-policy.yaml

# With JSON output
tlsanalyzer example.com --policy-file my-policy.yaml --format json

# Batch scanning with custom policy
tlsanalyzer --targets hosts.txt --policy-file my-policy.yaml --format html -o report.html
```

## Policy Inheritance

Use `extends` to inherit from built-in policies and override specific rules:

```yaml
name: my-strict-policy
version: "1.0"
description: Strict policy with custom certificate requirements
extends: strict

rules:
  certificate:
    minRsaKeySize: 4096
    minEccKeySize: 384
```

## Compliance Checking in CI/CD

```bash
# Exit with error if non-compliant
tlsanalyzer api.example.com --policy-file my-policy.yaml --format json | \
  jq -e '.policyResult.compliant == true'

# Get compliance score
SCORE=$(tlsanalyzer api.example.com --policy-file my-policy.yaml --format json | \
  jq -r '.policyResult.score')
echo "Compliance Score: $SCORE/100"

# Check specific violations
tlsanalyzer api.example.com --policy-file my-policy.yaml --format json | \
  jq '.policyResult.violations[]'
```

## Policy Validation

Before using a custom policy, validate its syntax:

```bash
# The tool will report YAML parsing errors
tlsanalyzer example.com --policy-file my-policy.yaml

# Check policy loading
tlsanalyzer policies  # Lists built-in policies
```

## Best Practices

1. **Start with a built-in policy** and customize as needed
2. **Version your policies** to track changes
3. **Store policies in version control** alongside your infrastructure code
4. **Use different policies** for different environments (dev, staging, prod)
5. **Regularly review and update** policies as requirements change
6. **Test policies** on a sample of targets before rolling out
