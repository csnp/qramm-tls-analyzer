# QRAMM TLS Analyzer

A quantum-ready TLS security assessment tool. Part of the [QRAMM](https://qramm.org) toolkit.

## Features

- **Protocol Analysis**: Detect supported TLS versions (1.0, 1.1, 1.2, 1.3)
- **Cipher Suite Assessment**: Evaluate cipher strength, forward secrecy, and deprecation status
- **Certificate Validation**: Check expiration, key strength, signature algorithms
- **Quantum Risk Assessment**: Evaluate readiness for post-quantum cryptography
  - Detect hybrid PQC key exchanges (X25519MLKEM768, etc.)
  - Assess harvest-now-decrypt-later (HNDL) attack risk
  - Provide actionable migration timelines
- **Vulnerability Detection**: Identify common TLS misconfigurations
- **Multiple Output Formats**: Text (with colors), JSON, SARIF

## Installation

```bash
go install github.com/csnp/qramm-tls-analyzer/cmd/tlsanalyzer@latest
```

Or build from source:

```bash
git clone https://github.com/csnp/qramm-tls-analyzer.git
cd qramm-tls-analyzer
go build -o tlsanalyzer ./cmd/tlsanalyzer
```

## Usage

```bash
# Basic scan
tlsanalyzer example.com

# Scan with custom port
tlsanalyzer example.com:8443

# JSON output for CI/CD integration
tlsanalyzer example.com --format json

# SARIF output for security tools
tlsanalyzer example.com --format sarif > report.sarif

# Disable colors for piping
tlsanalyzer example.com --no-color

# Quick scan (skip some checks)
tlsanalyzer example.com --skip-vulns --skip-quantum
```

## Output Example

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
  QUANTUM RISK ASSESSMENT
───────────────────────────────────────────────────────────────

    Risk Level:         CRITICAL
    Quantum Score:      0/100

    ✗ Hybrid PQC Key Exchange (e.g., X25519MLKEM768)
    ✗ Full PQC (ML-KEM key exchange + ML-DSA certificates)

    Recommended Action: IMMEDIATE - High priority for sensitive data
```

## Quantum Grades

| Grade | Meaning |
|-------|---------|
| Q+ | Quantum Ready - Using hybrid or full PQC |
| Q | Partially Ready - Some PQC protection |
| Q- | Limited Protection - Minimal quantum readiness |
| QV | Quantum Vulnerable - Classical crypto only |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed successfully |
| 1 | Scan failed (connection error, invalid target) |

## Configuration

All options can be provided via command-line flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--format, -f` | text | Output format (text, json, sarif) |
| `--timeout, -t` | 30 | Connection timeout in seconds |
| `--port, -p` | 443 | Target port |
| `--sni` | (from host) | Server Name Indication |
| `--no-color` | false | Disable colored output |
| `--compact` | false | Compact JSON output |
| `--skip-vulns` | false | Skip vulnerability checks |
| `--skip-quantum` | false | Skip quantum risk assessment |

## Integration

### CI/CD Pipeline

```yaml
# GitHub Actions example
- name: TLS Security Scan
  run: |
    tlsanalyzer api.example.com --format sarif > tls-report.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: tls-report.sarif
```

### JSON Processing

```bash
# Check if quantum vulnerable
tlsanalyzer example.com -f json | jq '.quantumRisk.level'

# Get grade
tlsanalyzer example.com -f json | jq '.grade.letter'
```

## Development

```bash
# Run tests
go test ./... -v

# Run tests with coverage
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out

# Build
go build -o tlsanalyzer ./cmd/tlsanalyzer
```

## Architecture

```
cmd/tlsanalyzer/     - CLI entry point
internal/
  scanner/           - TLS scanning and analysis
    scanner.go       - Core scanning logic
    quantum.go       - PQC risk assessment
    vulnerabilities.go - Vulnerability detection
    grade.go         - Grading system
    recommendations.go - Actionable recommendations
  reporter/          - Output formatters
    json.go          - JSON output
    text.go          - Human-readable text
    sarif.go         - SARIF for security tools
pkg/types/           - Public types and interfaces
```

## References

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203: ML-KEM](https://csrc.nist.gov/publications/detail/fips/203/final) - Key Encapsulation
- [FIPS 204: ML-DSA](https://csrc.nist.gov/publications/detail/fips/204/final) - Digital Signatures
- [RFC 8446: TLS 1.3](https://datatracker.ietf.org/doc/rfc8446/)
- [RFC 8996: Deprecating TLS 1.0 and 1.1](https://datatracker.ietf.org/doc/rfc8996/)

## License

Apache License 2.0

## Part of QRAMM

This tool is part of the Quantum Readiness Assurance Maturity Model (QRAMM) toolkit by [CSNP](https://csnp.org).
