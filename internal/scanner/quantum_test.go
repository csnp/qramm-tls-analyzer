package scanner

import (
	"testing"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

func TestQuantumVulnerableAlgorithms(t *testing.T) {
	// Ensure all expected vulnerable algorithms are present
	expected := []string{"RSA", "ECDSA", "ECDH", "DSA", "DH"}
	for _, algo := range expected {
		if _, ok := QuantumVulnerableAlgorithms[algo]; !ok {
			t.Errorf("expected %s to be in QuantumVulnerableAlgorithms", algo)
		}
	}
}

func TestQuantumSafeAlgorithms(t *testing.T) {
	// Ensure PQC algorithms are present
	expected := []string{"ML-KEM", "ML-DSA", "SLH-DSA", "AES-256", "ChaCha20"}
	for _, algo := range expected {
		if _, ok := QuantumSafeAlgorithms[algo]; !ok {
			t.Errorf("expected %s to be in QuantumSafeAlgorithms", algo)
		}
	}
}

func TestHybridKeyExchanges(t *testing.T) {
	tests := []struct {
		name      string
		classical string
		pqc       string
	}{
		{"X25519MLKEM768", "X25519", "ML-KEM-768"},
		{"SecP256r1MLKEM768", "P-256", "ML-KEM-768"},
		{"SecP384r1MLKEM1024", "P-384", "ML-KEM-1024"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ke, ok := HybridKeyExchanges[tt.name]
			if !ok {
				t.Fatalf("expected %s to be in HybridKeyExchanges", tt.name)
			}
			if ke.Classical != tt.classical {
				t.Errorf("expected classical %s, got %s", tt.classical, ke.Classical)
			}
			if ke.PQC != tt.pqc {
				t.Errorf("expected PQC %s, got %s", tt.pqc, ke.PQC)
			}
		})
	}
}

func TestAssessQuantumRisk(t *testing.T) {
	s := New(nil)

	tests := []struct {
		name        string
		result      *types.ScanResult
		wantLevel   types.RiskLevel
		wantHybrid  bool
		wantFullPQC bool
	}{
		{
			name: "classical only - critical risk",
			result: &types.ScanResult{
				KeyExchanges: []types.KeyExchange{
					{Name: "X25519", Type: "classical"},
				},
				Certificate: &types.Certificate{
					PublicKeyAlgorithm: "RSA",
				},
			},
			wantLevel:   types.RiskCritical,
			wantHybrid:  false,
			wantFullPQC: false,
		},
		{
			name: "hybrid key exchange - high risk",
			result: &types.ScanResult{
				KeyExchanges: []types.KeyExchange{
					{
						Name:           "X25519MLKEM768",
						Type:           "hybrid",
						HybridClassical: "X25519",
						PQCAlgorithm:   "ML-KEM-768",
					},
				},
				Certificate: &types.Certificate{
					PublicKeyAlgorithm: "RSA",
				},
			},
			wantLevel:   types.RiskHigh, // High because score = (80*60 + 0*40)/100 = 48 < 50
			wantHybrid:  true,
			wantFullPQC: false,
		},
		{
			name: "full PQC key exchange - medium risk",
			result: &types.ScanResult{
				KeyExchanges: []types.KeyExchange{
					{
						Name:         "ML-KEM-768",
						Type:         "pqc",
						PQCAlgorithm: "ML-KEM-768",
					},
				},
				Certificate: &types.Certificate{
					PublicKeyAlgorithm: "RSA",
				},
			},
			wantLevel:   types.RiskMedium, // Medium because score = (100*60 + 0*40)/100 = 60
			wantHybrid:  false,
			wantFullPQC: true,
		},
		{
			name: "full PQC everything - very low risk",
			result: &types.ScanResult{
				KeyExchanges: []types.KeyExchange{
					{
						Name:         "ML-KEM-768",
						Type:         "pqc",
						PQCAlgorithm: "ML-KEM-768",
					},
				},
				Certificate: &types.Certificate{
					PublicKeyAlgorithm: "ML-DSA",
				},
			},
			wantLevel:   types.RiskLow,
			wantHybrid:  false,
			wantFullPQC: true,
		},
		{
			name: "no key exchanges - infer from ciphers",
			result: &types.ScanResult{
				KeyExchanges: []types.KeyExchange{},
				CipherSuites: []types.CipherSuite{
					{KeyExchange: "ECDHE"},
				},
				Certificate: &types.Certificate{
					PublicKeyAlgorithm: "RSA",
				},
			},
			wantLevel:   types.RiskCritical,
			wantHybrid:  false,
			wantFullPQC: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assessment := s.assessQuantumRisk(tt.result)

			if assessment.Level != tt.wantLevel {
				t.Errorf("expected level %s, got %s", tt.wantLevel, assessment.Level)
			}
			if assessment.HybridPQCReady != tt.wantHybrid {
				t.Errorf("expected HybridPQCReady %v, got %v", tt.wantHybrid, assessment.HybridPQCReady)
			}
			if assessment.FullPQCReady != tt.wantFullPQC {
				t.Errorf("expected FullPQCReady %v, got %v", tt.wantFullPQC, assessment.FullPQCReady)
			}
		})
	}
}

func TestDescribeKeyExchangeRisk(t *testing.T) {
	tests := []struct {
		score    int
		contains string
	}{
		{100, "LOW"},
		{80, "LOW"},
		{50, "MEDIUM"},
		{0, "CRITICAL"},
	}

	for _, tt := range tests {
		t.Run(tt.contains, func(t *testing.T) {
			result := describeKeyExchangeRisk(tt.score)
			if !containsAny(result, tt.contains) {
				t.Errorf("expected result to contain %s, got %s", tt.contains, result)
			}
		})
	}
}

func TestDescribeCertificateRisk(t *testing.T) {
	tests := []struct {
		score    int
		contains string
	}{
		{100, "LOW"},
		{80, "LOW"},
		{50, "MEDIUM"},
		{0, "HIGH"},
	}

	for _, tt := range tests {
		t.Run(tt.contains, func(t *testing.T) {
			result := describeCertificateRisk(tt.score)
			if !containsAny(result, tt.contains) {
				t.Errorf("expected result to contain %s, got %s", tt.contains, result)
			}
		})
	}
}

func TestRecommendTimeToAction(t *testing.T) {
	tests := []struct {
		score    int
		contains string
	}{
		{100, "MONITORING"},
		{80, "MONITORING"},
		{50, "12-24 MONTHS"},
		{20, "6-12 MONTHS"},
		{0, "IMMEDIATE"},
	}

	for _, tt := range tests {
		t.Run(tt.contains, func(t *testing.T) {
			result := recommendTimeToAction(tt.score)
			if !containsAny(result, tt.contains) {
				t.Errorf("expected result to contain %s, got %s", tt.contains, result)
			}
		})
	}
}
