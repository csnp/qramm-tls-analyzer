package scanner

import (
	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// QuantumVulnerableAlgorithms lists algorithms vulnerable to quantum attacks.
var QuantumVulnerableAlgorithms = map[string]string{
	"RSA":   "Vulnerable to Shor's algorithm",
	"ECDSA": "Vulnerable to Shor's algorithm",
	"ECDH":  "Vulnerable to Shor's algorithm",
	"DSA":   "Vulnerable to Shor's algorithm",
	"DH":    "Vulnerable to Shor's algorithm",
}

// QuantumSafeAlgorithms lists post-quantum safe algorithms.
var QuantumSafeAlgorithms = map[string]string{
	"ML-KEM":       "NIST FIPS 203 - Key Encapsulation",
	"ML-DSA":       "NIST FIPS 204 - Digital Signatures",
	"SLH-DSA":      "NIST FIPS 205 - Stateless Hash-Based Signatures",
	"AES-256":      "Symmetric - Grover's algorithm requires 2^128 operations",
	"AES-128":      "Symmetric - Grover's algorithm requires 2^64 operations (marginal)",
	"ChaCha20":     "Symmetric - Quantum resistant",
	"SHA-256":      "Hash - Grover's provides only quadratic speedup",
	"SHA-384":      "Hash - Grover's provides only quadratic speedup",
	"SHA-512":      "Hash - Grover's provides only quadratic speedup",
}

// HybridKeyExchanges maps hybrid PQC key exchange names to components.
var HybridKeyExchanges = map[string]struct {
	Classical string
	PQC       string
}{
	"X25519MLKEM768":     {"X25519", "ML-KEM-768"},
	"SecP256r1MLKEM768":  {"P-256", "ML-KEM-768"},
	"SecP384r1MLKEM1024": {"P-384", "ML-KEM-1024"},
}

// assessQuantumRisk performs quantum-specific risk analysis.
func (s *Scanner) assessQuantumRisk(result *types.ScanResult) types.QuantumRiskAssessment {
	assessment := types.QuantumRiskAssessment{
		Details: []string{},
	}

	var keyExchangeScore int = 0
	var certScore int = 0
	var hybridPQC bool = false
	var fullPQC bool = false

	// Analyze key exchanges
	for _, ke := range result.KeyExchanges {
		switch ke.Type {
		case "pqc":
			keyExchangeScore = 100
			fullPQC = true
			assessment.Details = append(assessment.Details,
				"Key exchange uses full post-quantum cryptography: "+ke.PQCAlgorithm)
		case "hybrid":
			keyExchangeScore = 80
			hybridPQC = true
			assessment.Details = append(assessment.Details,
				"Key exchange uses hybrid PQC: "+ke.Name+" ("+ke.HybridClassical+" + "+ke.PQCAlgorithm+")")
		default:
			// Classical key exchange
			if _, vulnerable := QuantumVulnerableAlgorithms[ke.Name]; vulnerable {
				keyExchangeScore = 0
				assessment.Details = append(assessment.Details,
					"Key exchange "+ke.Name+" is vulnerable to quantum attacks (Shor's algorithm)")
			}
		}
	}

	// If no key exchanges found, assume classical from cipher suites
	if len(result.KeyExchanges) == 0 {
		for _, cs := range result.CipherSuites {
			if cs.KeyExchange == "RSA" || cs.KeyExchange == "ECDHE" || cs.KeyExchange == "DHE" {
				assessment.Details = append(assessment.Details,
					"Key exchange "+cs.KeyExchange+" is vulnerable to quantum attacks")
				break
			}
		}
	}

	// Analyze certificate
	if result.Certificate != nil {
		cert := result.Certificate

		switch cert.PublicKeyAlgorithm {
		case "RSA":
			certScore = 0
			assessment.Details = append(assessment.Details,
				"Certificate uses RSA, vulnerable to Shor's algorithm")
		case "ECDSA", "Ed25519":
			certScore = 0
			assessment.Details = append(assessment.Details,
				"Certificate uses elliptic curve cryptography, vulnerable to Shor's algorithm")
		case "ML-DSA", "CRYSTALS-Dilithium":
			certScore = 100
			fullPQC = true
			assessment.Details = append(assessment.Details,
				"Certificate uses post-quantum signature algorithm")
		case "SLH-DSA", "SPHINCS+":
			certScore = 100
			fullPQC = true
			assessment.Details = append(assessment.Details,
				"Certificate uses post-quantum hash-based signatures")
		}

		// Check signature algorithm
		if containsAny(cert.SignatureAlgorithm, "RSA", "ECDSA") {
			assessment.Details = append(assessment.Details,
				"Certificate signature algorithm "+cert.SignatureAlgorithm+" is quantum-vulnerable")
		}
	}

	// Calculate overall score
	// Weight: 60% key exchange (immediate threat), 40% certificate
	assessment.Score = (keyExchangeScore*60 + certScore*40) / 100
	assessment.HybridPQCReady = hybridPQC
	assessment.FullPQCReady = fullPQC

	// Determine risk level
	switch {
	case assessment.Score >= 80:
		assessment.Level = types.RiskLow
	case assessment.Score >= 50:
		assessment.Level = types.RiskMedium
	case assessment.Score >= 20:
		assessment.Level = types.RiskHigh
	default:
		assessment.Level = types.RiskCritical
	}

	// Set risk descriptions
	assessment.KeyExchangeRisk = describeKeyExchangeRisk(keyExchangeScore)
	assessment.CertificateRisk = describeCertificateRisk(certScore)
	assessment.HNDLRisk = describeHNDLRisk(result)
	assessment.TimeToAction = recommendTimeToAction(assessment.Score)

	return assessment
}

func describeKeyExchangeRisk(score int) string {
	switch {
	case score >= 80:
		return "LOW - Using hybrid or full PQC key exchange"
	case score >= 50:
		return "MEDIUM - Partial quantum protection"
	default:
		return "CRITICAL - Classical key exchange vulnerable to harvest-now-decrypt-later attacks"
	}
}

func describeCertificateRisk(score int) string {
	switch {
	case score >= 80:
		return "LOW - Using post-quantum signatures"
	case score >= 50:
		return "MEDIUM - Partial quantum protection"
	default:
		return "HIGH - Classical signatures can be forged by quantum computers (future threat)"
	}
}

func describeHNDLRisk(result *types.ScanResult) string {
	// Harvest Now, Decrypt Later risk assessment
	// This depends on data sensitivity and key exchange vulnerability

	hasForwardSecrecy := false
	for _, cs := range result.CipherSuites {
		if cs.ForwardSecrecy {
			hasForwardSecrecy = true
			break
		}
	}

	hasPQCKeyExchange := false
	for _, ke := range result.KeyExchanges {
		if ke.Type == "hybrid" || ke.Type == "pqc" {
			hasPQCKeyExchange = true
			break
		}
	}

	if hasPQCKeyExchange {
		return "LOW - PQC key exchange protects against HNDL attacks"
	}
	if hasForwardSecrecy {
		return "HIGH - Forward secrecy helps but doesn't protect against quantum decryption"
	}
	return "CRITICAL - No forward secrecy; all recorded traffic decryptable when quantum computers arrive"
}

func recommendTimeToAction(score int) string {
	switch {
	case score >= 80:
		return "MONITORING - Continue monitoring PQC developments"
	case score >= 50:
		return "12-24 MONTHS - Plan migration to full PQC"
	case score >= 20:
		return "6-12 MONTHS - Begin hybrid PQC implementation"
	default:
		return "IMMEDIATE - High priority for organizations with sensitive data"
	}
}
