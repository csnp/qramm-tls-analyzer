<h1 align="center">QRAMM TLS Analyzer</h1>

<p align="center">
  <strong>Quantum-Ready TLS Security Assessment Tool</strong>
</p>

<p align="center">
  <a href="https://github.com/csnp/qramm-tls-analyzer/actions"><img src="https://github.com/csnp/qramm-tls-analyzer/workflows/CI/badge.svg" alt="CI Status"></a>
  <a href="https://goreportcard.com/report/github.com/csnp/qramm-tls-analyzer"><img src="https://goreportcard.com/badge/github.com/csnp/qramm-tls-analyzer" alt="Go Report Card"></a>
  <a href="https://pkg.go.dev/github.com/csnp/qramm-tls-analyzer"><img src="https://pkg.go.dev/badge/github.com/csnp/qramm-tls-analyzer.svg" alt="Go Reference"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#features">Features</a> &bull;
  <a href="#installation">Installation</a> &bull;
  <a href="#usage">Usage</a> &bull;
  <a href="#output-formats">Output Formats</a> &bull;
  <a href="#policies">Policies</a> &bull;
  <a href="#contributing">Contributing</a>
</p>

---

## Overview

**QRAMM TLS Analyzer** is an open-source command-line tool that performs comprehensive TLS security analysis with a focus on **post-quantum cryptography (PQC) readiness**. As quantum computing advances, organizations must prepare their cryptographic infrastructure for the post-quantum era. This tool helps you understand your current TLS posture and provides actionable guidance for CNSA 2.0 compliance.

Part of the [QRAMM (Quantum Readiness Assurance Maturity Model)](https://qramm.org) toolkit, developed by the [Cyber Security Non-Profit (CSNP)](https://csnp.org).

> **⚠️ Responsible Use Warning**
>
> This tool performs active network connections to analyze TLS configurations. **Only scan systems and domains you own or have explicit written authorization to test.** Unauthorized scanning may violate laws and regulations in your jurisdiction. The authors assume no liability for misuse of this tool.

### Why Quantum Readiness Matters

- **Harvest Now, Decrypt Later (HNDL)**: Adversaries are collecting encrypted data today to decrypt once quantum computers become available
- **CNSA 2.0 Deadlines**: NSA's timeline requires hybrid PQC for new systems by 2027 and full transition by 2035
- **Long Migration Cycles**: Cryptographic migrations typically take 5-10 years to complete
- **Regulatory Pressure**: Government agencies and regulated industries must demonstrate quantum readiness

## Quick Start

```bash
# Install
go install github.com/csnp/qramm-tls-analyzer/cmd/tlsanalyzer@latest

# Scan a target
tlsanalyzer example.com

# Evaluate against CNSA 2.0 policy
tlsanalyzer example.com --policy cnsa-2.0-2027

# Generate HTML report
tlsanalyzer example.com --format html -o report.html

# Generate cryptographic inventory (CBOM)
tlsanalyzer example.com --format cbom -o crypto-inventory.json
```

## Features

### Security Analysis

| Feature | Description |
|---------|-------------|
| **Protocol Analysis** | TLS 1.0, 1.1, 1.2, 1.3 version detection with deprecation warnings |
| **Cipher Suite Evaluation** | Strength assessment, forward secrecy verification, weak algorithm detection |
| **Certificate Analysis** | Validity, chain verification, key strength, signature algorithm assessment |
| **Vulnerability Detection** | BEAST, POODLE, weak ciphers, expired certificates, and more |

### Quantum Readiness

| Feature | Description |
|---------|-------------|
| **Quantum Risk Scoring** | 0-100 score indicating quantum vulnerability |
| **PQC Detection** | ML-KEM, ML-DSA, SLH-DSA, and hybrid key exchange detection |
| **HNDL Risk Assessment** | Evaluate exposure to harvest-now-decrypt-later attacks |
| **CNSA 2.0 Timeline** | Track compliance against NSA's post-quantum migration deadlines |

### Compliance & Reporting

| Feature | Description |
|---------|-------------|
| **Policy-as-Code** | Built-in and custom YAML policies for automated compliance checking |
| **CNSA 2.0 Timeline Tracking** | Milestones for 2025, 2027, 2030, 2033, 2035 |
| **Multiple Output Formats** | Text, JSON, SARIF, CycloneDX CBOM, HTML |
| **Batch Scanning** | Scan multiple targets with concurrency control |

## Installation

### From Source

```bash
# Requires Go 1.21+
git clone https://github.com/csnp/qramm-tls-analyzer.git
cd qramm-tls-analyzer
go build -o tlsanalyzer ./cmd/tlsanalyzer
```

### Using Go Install

```bash
go install github.com/csnp/qramm-tls-analyzer/cmd/tlsanalyzer@latest
```

### Pre-built Binaries

Download from [Releases](https://github.com/csnp/qramm-tls-analyzer/releases) for:
- Linux (amd64, arm64)
- macOS (amd64, arm64)
- Windows (amd64)

## Usage

### Basic Scan

```bash
# Scan a single target
tlsanalyzer example.com

# Specify port
tlsanalyzer example.com:8443

# Custom timeout
tlsanalyzer example.com --timeout 60

# Custom SNI
tlsanalyzer 192.168.1.1 --sni example.com
```

### Output Formats

```bash
# Human-readable text (default)
tlsanalyzer example.com

# JSON output
tlsanalyzer example.com --format json

# Compact JSON (no indentation)
tlsanalyzer example.com --format json --compact

# SARIF (for GitHub/Azure DevOps security integration)
tlsanalyzer example.com --format sarif -o results.sarif

# CycloneDX CBOM (Cryptographic Bill of Materials)
tlsanalyzer example.com --format cbom -o crypto-inventory.json

# HTML report (standalone, shareable)
tlsanalyzer example.com --format html -o report.html
```

### Policy Evaluation

```bash
# List available policies
tlsanalyzer policies

# Evaluate against built-in policy
tlsanalyzer example.com --policy cnsa-2.0-2027

# Use custom policy file
tlsanalyzer example.com --policy-file custom-policy.yaml
```

### Batch Scanning

```bash
# Create a targets file (one per line)
echo "example.com
api.example.com
staging.example.com" > hosts.txt

# Scan all targets
tlsanalyzer --targets hosts.txt --format json -o results.json

# Control concurrency (default: 10)
tlsanalyzer --targets hosts.txt --concurrency 20

# Generate summary report
tlsanalyzer --targets hosts.txt --format html -o batch-report.html
```

### Skip Options

```bash
# Skip vulnerability checks (faster scan)
tlsanalyzer example.com --skip-vulns

# Skip quantum assessment
tlsanalyzer example.com --skip-quantum

# Skip CNSA 2.0 analysis
tlsanalyzer example.com --skip-cnsa2
```

## Output Formats

### Text Output

Beautiful terminal output with color-coded results:

```
═══════════════════════════════════════════════════════════════
  QRAMM TLS Analyzer - Quantum-Ready Security Assessment
═══════════════════════════════════════════════════════════════

  Target: example.com
  IP: 93.184.216.34
  Scanned: 2025-01-15 10:30:00 UTC

───────────────────────────────────────────────────────────────
  OVERALL GRADE
───────────────────────────────────────────────────────────────

  TLS Security:     B    (78/100)
  Quantum Ready:    QV

  Score Breakdown:
    Protocol Support     [████████████████░░░░] 20/25
    Cipher Strength      [████████████████████] 25/25
    Certificate          [████████████████████] 25/25
    Quantum Readiness    [░░░░░░░░░░░░░░░░░░░░] 0/25

───────────────────────────────────────────────────────────────
  POLICY EVALUATION
───────────────────────────────────────────────────────────────

    Policy:     cnsa-2.0-2027
    Status:     ✗ NON-COMPLIANT
    Score:      10/100

    Violations (4)
      • [CRITICAL] Required key exchange algorithm not found
        Expected: X25519MLKEM768 or SecP384r1MLKEM1024

───────────────────────────────────────────────────────────────
  CNSA 2.0 COMPLIANCE TIMELINE
───────────────────────────────────────────────────────────────

    Current Phase:      Preparation Phase
    Timeline Score:     54/100
    Days to Deadline:   371
    Next Action:        Enable hybrid PQC key exchange

    Milestones:
      ○ Preparation Phase (2025-12-31)
      ✗ New NSS Systems (2027-01-01)
         └─ ML-KEM key exchange not detected
      ◐ TLS 1.3 Required (2030-01-02)
      — Legacy System Update (2033-01-01)
      — Full PQC Transition (2035-01-01)
```

### JSON Output

Machine-readable output for automation and integration:

```json
{
  "target": "example.com",
  "host": "example.com",
  "port": 443,
  "ip": "93.184.216.34",
  "grade": {
    "letter": "B",
    "score": 78,
    "quantumGrade": "QV"
  },
  "quantumRisk": {
    "score": 0,
    "level": "CRITICAL",
    "hybridPqcReady": false,
    "fullPqcReady": false
  },
  "cnsa2Timeline": {
    "currentPhase": "Preparation Phase",
    "timelineScore": 54,
    "daysToNextDeadline": 371,
    "nextAction": "Enable hybrid PQC key exchange"
  },
  "policyResult": {
    "policyName": "cnsa-2.0-2027",
    "compliant": false,
    "score": 10,
    "violations": [...]
  }
}
```

### CycloneDX CBOM

Cryptographic Bill of Materials for asset inventory and supply chain security:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-15T10:30:00Z",
    "tools": [{"vendor": "CSNP", "name": "qramm-tls-analyzer", "version": "0.2.0"}]
  },
  "components": [
    {
      "type": "cryptographic-asset",
      "bom-ref": "protocol-example.com-TLS 1.3",
      "name": "TLS 1.3",
      "cryptoProperties": {
        "assetType": "protocol",
        "protocolProperties": {"type": "tls", "version": "TLS 1.3"}
      }
    },
    {
      "type": "cryptographic-asset",
      "name": "TLS_AES_256_GCM_SHA384",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "ae",
          "mode": "gcm",
          "classicalSecurityLevel": 256
        }
      }
    }
  ],
  "services": [
    {
      "bom-ref": "service-example.com",
      "name": "example.com",
      "endpoints": ["https://example.com:443"]
    }
  ]
}
```

### HTML Report

Standalone HTML reports with embedded CSS for sharing with executives and stakeholders:

- Executive summary with grade visualization
- Quantum risk assessment with visual indicators
- CNSA 2.0 timeline with milestone tracking
- Detailed findings with remediation guidance
- Dark theme, responsive design
- No external dependencies (fully standalone)

## Policies

### Built-in Policies

| Policy | Description | Target Year |
|--------|-------------|-------------|
| `modern` | Modern TLS configuration for 2024+ | - |
| `strict` | Strict TLS 1.3-only configuration | - |
| `cnsa-2.0-2027` | CNSA 2.0 for new NSS systems | 2027 |
| `cnsa-2.0-2030` | CNSA 2.0 with TLS 1.3 required | 2030 |
| `cnsa-2.0-2035` | CNSA 2.0 full PQC transition | 2035 |

```bash
# List all available policies with descriptions
tlsanalyzer policies

Available Security Policies:
─────────────────────────────────────────────────────────

  modern
    Modern TLS configuration for 2024+

  strict
    Strict TLS configuration with TLS 1.3 required

  cnsa-2.0-2027
    CNSA 2.0 compliance target for 2027 - new NSS systems
    CNSA 2.0 Target: 2027

  cnsa-2.0-2030
    CNSA 2.0 compliance target for 2030 - TLS 1.3 required
    CNSA 2.0 Target: 2030

  cnsa-2.0-2035
    CNSA 2.0 compliance target for 2035 - full PQC
    CNSA 2.0 Target: 2035
```

### Custom Policies

Create custom policies in YAML format:

```yaml
# my-organization-policy.yaml
name: my-organization-policy
version: "1.0"
description: Custom security policy for my organization
extends: modern  # Inherit from built-in policy

rules:
  protocol:
    minVersion: TLS 1.3
    requiredVersions:
      - TLS 1.3
    bannedVersions:
      - TLS 1.0
      - TLS 1.1
      - TLS 1.2

  cipher:
    minKeySize: 256
    requireForwardSecrecy: true
    bannedAlgorithms:
      - 3DES
      - RC4
      - MD5
      - SHA1
    bannedCipherSuites:
      - TLS_RSA_WITH_AES_128_CBC_SHA

  certificate:
    minValidityDays: 30
    minRsaKeySize: 3072
    minEccKeySize: 384
    bannedSignatureAlgorithms:
      - SHA1
      - MD5
    allowSelfSigned: false

  quantum:
    requireHybridKeyExchange: true
    minQuantumScore: 50
    cnsa2TargetYear: 2027
    requiredKeyExchangeAlgorithms:
      - ML-KEM-768
      - ML-KEM-1024
```

Use your custom policy:

```bash
tlsanalyzer example.com --policy-file my-organization-policy.yaml
```

## CNSA 2.0 Timeline

The tool tracks compliance against NSA's Commercial National Security Algorithm Suite 2.0 timeline:

| Milestone | Deadline | Requirements |
|-----------|----------|--------------|
| **Preparation Phase** | Dec 2025 | Begin PQC integration planning, inventory cryptographic assets |
| **New NSS Systems** | Jan 2027 | ML-KEM for key exchange, ML-DSA/SLH-DSA for signatures, AES-256, SHA-384+ |
| **TLS 1.3 Required** | Jan 2030 | TLS 1.3 mandatory, hybrid PQC required, RSA/ECDH no longer acceptable |
| **Legacy System Update** | Jan 2033 | Complete migration of all existing systems, PQC certificates deployed |
| **Full PQC Transition** | Jan 2035 | Pure PQC (no hybrid required), classical algorithms fully retired |

### Algorithm Classification

| Status | Description | Examples |
|--------|-------------|----------|
| **Approved** | CNSA 2.0 approved | ML-KEM-768, ML-KEM-1024, ML-DSA-65, ML-DSA-87, SLH-DSA, AES-256, SHA-384, SHA-512 |
| **Transitional** | Allowed until deadline | RSA-3072, RSA-4096, ECDSA-P384, ECDH-P384, X25519 (hybrid only), SHA-256 |
| **Deprecated** | Phase out immediately | RSA-2048, ECDSA-P256, ECDH-P256 |
| **Prohibited** | Never use | 3DES, RC4, SHA-1, MD5 |

## Grading System

### TLS Security Grade

| Grade | Score | Description |
|-------|-------|-------------|
| **A+** | 95-100 | Exceptional security with quantum readiness |
| **A** | 85-94 | Excellent configuration |
| **B** | 70-84 | Good with minor improvements needed |
| **C** | 55-69 | Adequate but significant improvements recommended |
| **D** | 40-54 | Poor configuration, security issues present |
| **F** | 0-39 | Failing, critical vulnerabilities |

### Quantum Readiness Grade

| Grade | Description |
|-------|-------------|
| **Q+** | Full PQC ready (ML-KEM key exchange + ML-DSA certificates) |
| **Q** | Hybrid PQC key exchange enabled |
| **Q-** | Partially quantum-ready |
| **QV** | Quantum vulnerable (classical cryptography only) |

## CLI Reference

```
USAGE:
  tlsanalyzer [target] [flags]
  tlsanalyzer [command]

COMMANDS:
  policies    List available security policies
  version     Print version information

FLAGS:
  -f, --format string      Output format: text, json, sarif, cbom, html (default "text")
  -o, --output string      Output file (default: stdout)
  -t, --timeout int        Connection timeout in seconds (default 30)
  -p, --port int           Target port (default 443)
      --sni string         Server Name Indication (SNI)
      --no-color           Disable colored output
      --compact            Compact JSON output
      --skip-vulns         Skip vulnerability checks
      --skip-quantum       Skip quantum risk assessment
      --skip-cnsa2         Skip CNSA 2.0 compliance analysis
      --policy string      Apply a security policy
      --policy-file string Path to custom policy YAML file
      --targets string     File containing list of targets
  -c, --concurrency int    Concurrent scans for batch mode (default 10)
  -h, --help              Help for tlsanalyzer
```

## Integration

### CI/CD Integration

**GitHub Actions:**
```yaml
name: TLS Security Scan

on:
  schedule:
    - cron: '0 0 * * *'  # Daily
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Install TLS Analyzer
        run: go install github.com/csnp/qramm-tls-analyzer/cmd/tlsanalyzer@latest

      - name: Scan Production
        run: tlsanalyzer api.example.com --format sarif -o tls-results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: tls-results.sarif

      - name: Check Policy Compliance
        run: |
          tlsanalyzer api.example.com --policy cnsa-2.0-2027 --format json | \
            jq -e '.policyResult.compliant == true' || exit 1
```

**GitLab CI:**
```yaml
tls_security_scan:
  image: golang:1.21
  script:
    - go install github.com/csnp/qramm-tls-analyzer/cmd/tlsanalyzer@latest
    - tlsanalyzer $TARGET --format json -o tls-report.json
    - tlsanalyzer $TARGET --policy $POLICY --format json | jq '.policyResult.compliant'
  artifacts:
    reports:
      security: tls-report.json
```

### SBOM Integration

Generate CycloneDX CBOM for integration with software bill of materials tools:

```bash
# Generate cryptographic BOM
tlsanalyzer example.com --format cbom -o crypto-bom.json

# Merge with existing SBOM using CycloneDX CLI
cyclonedx merge --input-files sbom.json crypto-bom.json --output merged-sbom.json

# Validate CBOM
cyclonedx validate --input-file crypto-bom.json
```

### Automation with JSON

```bash
# Check if quantum vulnerable
QUANTUM_LEVEL=$(tlsanalyzer example.com -f json | jq -r '.quantumRisk.level')
if [ "$QUANTUM_LEVEL" = "CRITICAL" ]; then
  echo "WARNING: Quantum vulnerable configuration detected"
  exit 1
fi

# Get overall grade
GRADE=$(tlsanalyzer example.com -f json | jq -r '.grade.letter')
echo "TLS Grade: $GRADE"

# Check policy compliance
COMPLIANT=$(tlsanalyzer example.com --policy cnsa-2.0-2027 -f json | jq -r '.policyResult.compliant')
echo "CNSA 2.0 Compliant: $COMPLIANT"
```

## Architecture

```
qramm-tls-analyzer/
├── cmd/
│   └── tlsanalyzer/
│       └── main.go           # CLI entry point, flag parsing, batch scanning
├── internal/
│   ├── analyzer/
│   │   ├── cnsa2.go          # CNSA 2.0 compliance analysis
│   │   └── policy.go         # Policy-as-code evaluation
│   ├── reporter/
│   │   ├── cbom.go           # CycloneDX CBOM output
│   │   ├── html.go           # HTML report generation
│   │   ├── json.go           # JSON output
│   │   ├── sarif.go          # SARIF output
│   │   └── text.go           # Terminal output with colors
│   └── scanner/
│       ├── scanner.go        # Core TLS scanning logic
│       ├── quantum.go        # PQC risk assessment
│       ├── vulnerabilities.go # Vulnerability detection
│       ├── grade.go          # Grading system
│       └── recommendations.go # Actionable recommendations
└── pkg/
    └── types/
        ├── result.go         # Scan result types
        ├── policy.go         # Policy definitions
        ├── cbom.go           # CycloneDX CBOM types
        └── compliance.go     # Compliance framework types
```

## About QRAMM

**QRAMM (Quantum Readiness Assurance Maturity Model)** is an evidence-based framework designed to help enterprises systematically prepare for the quantum computing threat to current cryptographic systems. QRAMM provides structured evaluation across quantum readiness dimensions.

Visit [qramm.org](https://qramm.org) to learn more about:
- Quantum readiness assessment
- Migration planning resources
- Implementation guidance
- Industry benchmarks

### QRAMM Toolkit

This analyzer is part of the QRAMM open-source toolkit:

| Tool | Description |
|------|-------------|
| **TLS Analyzer** | TLS/SSL configuration analysis with quantum readiness (this tool) |
| **CryptoScan** | Cryptographic discovery scanner for codebases |
| **CryptoCBOM** | Cryptographic Bill of Materials generator |
| **KeyRotate** | Key rotation automation framework |
| **QRAMM CLI** | Assessment and planning command-line interface |

## About CSNP

The **Cyber Security Non-Profit (CSNP)** exists to democratize cybersecurity knowledge and make it accessible to everyone, regardless of background, resources, or technical expertise.

**Our Mission:** We believe that security should not be a privilege but a right. Our mission is to empower individuals, families, businesses, and communities with the knowledge and tools they need to protect themselves in the digital world.

**Our Vision:** We envision a world where everyone has access to the cybersecurity knowledge they need to participate safely and confidently in the digital society. Through free education, community building, and practical resources, we aim to create a more secure digital future for all.

**Core Values:**
- **Accessibility** - Cybersecurity knowledge should be available to everyone
- **Community** - Building a global network of empowered security practitioners
- **Transparency** - Open-source tools and freely available resources
- **Practicality** - Real-world, actionable security guidance

Visit [csnp.org](https://csnp.org) to learn more.

## Contributing

We welcome contributions from the community! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone repository
git clone https://github.com/csnp/qramm-tls-analyzer.git
cd qramm-tls-analyzer

# Install dependencies
go mod download

# Run tests
go test ./... -v

# Run tests with coverage
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out

# Build
go build -o tlsanalyzer ./cmd/tlsanalyzer

# Run linter
go vet ./...
```

### Running Tests

```bash
# All tests
go test ./...

# With coverage
go test ./... -cover

# Specific package
go test ./internal/analyzer/... -v

# Short tests only
go test ./... -short
```

## References

- [NSA CNSA 2.0 Guidance](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF) - Commercial National Security Algorithm Suite 2.0
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography) - PQC Standardization
- [FIPS 203: ML-KEM](https://csrc.nist.gov/publications/detail/fips/203/final) - Module-Lattice Key Encapsulation
- [FIPS 204: ML-DSA](https://csrc.nist.gov/publications/detail/fips/204/final) - Module-Lattice Digital Signatures
- [FIPS 205: SLH-DSA](https://csrc.nist.gov/publications/detail/fips/205/final) - Stateless Hash-Based Digital Signatures
- [RFC 8446: TLS 1.3](https://datatracker.ietf.org/doc/rfc8446/) - Transport Layer Security 1.3
- [RFC 8996: Deprecating TLS 1.0 and 1.1](https://datatracker.ietf.org/doc/rfc8996/)
- [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/) - Cryptographic Bill of Materials

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- NSA's CNSA 2.0 guidance for post-quantum cryptography standards
- NIST for PQC algorithm standardization (ML-KEM, ML-DSA, SLH-DSA)
- The Go team for excellent TLS library support
- CycloneDX for the CBOM specification
- Our amazing contributors and the open-source community

---

<p align="center">
  <strong>Built with purpose by <a href="https://csnp.org">CSNP</a></strong>
</p>

<p align="center">
  <a href="https://qramm.org">QRAMM</a> &bull;
  <a href="https://csnp.org">CSNP</a> &bull;
  <a href="https://github.com/csnp/qramm-tls-analyzer/issues">Report Bug</a> &bull;
  <a href="https://github.com/csnp/qramm-tls-analyzer/issues">Request Feature</a>
</p>
