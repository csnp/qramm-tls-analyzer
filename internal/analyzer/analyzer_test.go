package analyzer

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

func createTestResult() *types.ScanResult {
	return &types.ScanResult{
		Target:         "example.com",
		Host:           "example.com",
		Port:           443,
		IP:             "93.184.216.34",
		Timestamp:      time.Now(),
		ScannerVersion: "0.2.0",
		Protocols: []types.Protocol{
			{Version: "TLS 1.3", Supported: true, Preferred: true},
			{Version: "TLS 1.2", Supported: true},
		},
		CipherSuites: []types.CipherSuite{
			{
				ID:             0x1301,
				Name:           "TLS_AES_128_GCM_SHA256",
				Protocol:       "TLS 1.3",
				ForwardSecrecy: true,
				Bits:           128,
				Encryption:     "AES-GCM",
			},
		},
		KeyExchanges: []types.KeyExchange{
			{
				Name:        "X25519",
				Type:        "ecdhe",
				QuantumSafe: false,
			},
		},
		Certificate: &types.Certificate{
			Subject:            "CN=example.com",
			Issuer:             "CN=DigiCert TLS RSA SHA256 2020 CA1",
			NotBefore:          time.Now().AddDate(0, -6, 0),
			NotAfter:           time.Now().AddDate(0, 6, 0),
			SignatureAlgorithm: "SHA256WithRSA",
			PublicKeyAlgorithm: "RSA",
			PublicKeyBits:      2048,
			DaysUntilExpiry:    180,
		},
	}
}

func createQuantumReadyResult() *types.ScanResult {
	return &types.ScanResult{
		Target:         "quantum-ready.example.com",
		Host:           "quantum-ready.example.com",
		Port:           443,
		Timestamp:      time.Now(),
		ScannerVersion: "0.2.0",
		Protocols: []types.Protocol{
			{Version: "TLS 1.3", Supported: true, Preferred: true},
		},
		CipherSuites: []types.CipherSuite{
			{
				ID:             0x1301,
				Name:           "TLS_AES_256_GCM_SHA384",
				Protocol:       "TLS 1.3",
				ForwardSecrecy: true,
				Bits:           256,
				Encryption:     "AES-GCM",
				QuantumSafe:    true,
			},
		},
		KeyExchanges: []types.KeyExchange{
			{
				Name:            "X25519MLKEM768",
				Type:            "hybrid",
				QuantumSafe:     true,
				PQCAlgorithm:    "ML-KEM-768",
				HybridClassical: "X25519",
			},
		},
		Certificate: &types.Certificate{
			Subject:            "CN=quantum-ready.example.com",
			Issuer:             "CN=DigiCert TLS RSA SHA256 2020 CA1",
			NotBefore:          time.Now().AddDate(0, -6, 0),
			NotAfter:           time.Now().AddDate(0, 6, 0),
			SignatureAlgorithm: "ML-DSA-65",
			PublicKeyAlgorithm: "ML-DSA",
			PublicKeyBits:      256,
			DaysUntilExpiry:    180,
			QuantumSafe:        true,
		},
	}
}

// CNSA 2.0 Analyzer Tests

func TestCNSA2AnalyzerAnalyze(t *testing.T) {
	analyzer := NewCNSA2Analyzer()
	result := createTestResult()

	timeline := analyzer.Analyze(result)

	if timeline == nil {
		t.Fatal("Analyze() returned nil")
	}

	// Should have assessment date
	if timeline.AssessmentDate.IsZero() {
		t.Error("AssessmentDate should be set")
	}

	// Should have milestones
	if len(timeline.Milestones) == 0 {
		t.Error("should have at least one milestone")
	}

	// Classical-only result should have findings about quantum readiness
	if len(timeline.Findings) == 0 {
		t.Error("classical result should have CNSA 2.0 findings")
	}

	// Should determine current phase
	if timeline.CurrentPhase == "" {
		t.Error("CurrentPhase should be set")
	}
}

func TestCNSA2AnalyzerQuantumReady(t *testing.T) {
	analyzer := NewCNSA2Analyzer()
	result := createQuantumReadyResult()

	timeline := analyzer.Analyze(result)

	if timeline == nil {
		t.Fatal("Analyze() returned nil")
	}

	// Quantum-ready should have higher score
	if timeline.TimelineScore < 50 {
		t.Errorf("quantum-ready result should have higher score, got %d", timeline.TimelineScore)
	}
}

func TestCNSA2AlgorithmClassifications(t *testing.T) {
	// Test approved key exchange algorithms
	approvedKE := []string{"ML-KEM-768", "ML-KEM-1024", "X25519MLKEM768"}
	for _, alg := range approvedKE {
		if !CNSA2ApprovedKeyExchange[alg] {
			t.Errorf("%s should be in CNSA2ApprovedKeyExchange", alg)
		}
	}

	// Test approved signatures
	approvedSig := []string{"ML-DSA-65", "ML-DSA-87"}
	for _, alg := range approvedSig {
		if !CNSA2ApprovedSignatures[alg] {
			t.Errorf("%s should be in CNSA2ApprovedSignatures", alg)
		}
	}

	// Test transitional algorithms
	if _, ok := CNSA2Transitional["RSA-3072"]; !ok {
		t.Error("RSA-3072 should be in CNSA2Transitional")
	}

	// Test deprecated algorithms
	if _, ok := CNSA2Deprecated["RSA-2048"]; !ok {
		t.Error("RSA-2048 should be in CNSA2Deprecated")
	}
}

func TestCNSA2Milestones(t *testing.T) {
	if len(CNSA2Milestones) != 5 {
		t.Errorf("expected 5 CNSA 2.0 milestones, got %d", len(CNSA2Milestones))
	}

	// Check milestone names
	expectedNames := []string{
		"Preparation Phase",
		"New NSS Systems",
		"TLS 1.3 Required",
		"Legacy System Update",
		"Full PQC Transition",
	}

	for i, expected := range expectedNames {
		if CNSA2Milestones[i].Name != expected {
			t.Errorf("milestone %d: got %s, want %s", i, CNSA2Milestones[i].Name, expected)
		}
	}
}

// Policy Evaluator Tests

func TestPolicyEvaluatorListPolicies(t *testing.T) {
	evaluator := NewPolicyEvaluator()
	policies := evaluator.ListPolicies()

	if len(policies) == 0 {
		t.Fatal("ListPolicies() returned no policies")
	}

	// Should have built-in policies
	expectedPolicies := []string{"modern", "strict", "cnsa-2.0-2027", "cnsa-2.0-2030", "cnsa-2.0-2035"}
	for _, expected := range expectedPolicies {
		found := false
		for _, p := range policies {
			if p == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected policy %s not found", expected)
		}
	}
}

func TestPolicyEvaluatorGetPolicy(t *testing.T) {
	evaluator := NewPolicyEvaluator()

	policy, ok := evaluator.GetPolicy("modern")
	if !ok {
		t.Fatal("GetPolicy(modern) returned false")
	}

	if policy.Name != "modern" {
		t.Errorf("policy.Name = %s, want modern", policy.Name)
	}

	if policy.Description == "" {
		t.Error("policy should have description")
	}
}

func TestPolicyEvaluatorGetPolicyNotFound(t *testing.T) {
	evaluator := NewPolicyEvaluator()

	_, ok := evaluator.GetPolicy("nonexistent")
	if ok {
		t.Error("GetPolicy(nonexistent) should return false")
	}
}

func TestPolicyEvaluatorEvaluate(t *testing.T) {
	evaluator := NewPolicyEvaluator()
	result := createTestResult()

	policy, _ := evaluator.GetPolicy("modern")
	policyResult := evaluator.Evaluate(result, policy)

	if policyResult == nil {
		t.Fatal("Evaluate() returned nil")
	}

	if policyResult.PolicyName != "modern" {
		t.Errorf("PolicyName = %s, want modern", policyResult.PolicyName)
	}
}

func TestPolicyEvaluatorEvaluateQuantumPolicy(t *testing.T) {
	evaluator := NewPolicyEvaluator()
	result := createTestResult()

	policy, _ := evaluator.GetPolicy("cnsa-2.0-2027")
	policyResult := evaluator.Evaluate(result, policy)

	if policyResult == nil {
		t.Fatal("Evaluate() returned nil")
	}

	// Classical-only result should fail quantum policy
	if policyResult.Compliant {
		t.Error("classical result should not pass CNSA 2.0 policy")
	}

	// Should have violations
	if len(policyResult.Violations) == 0 {
		t.Error("should have policy violations for classical crypto")
	}
}

func TestPolicyEvaluatorLoadPolicy(t *testing.T) {
	evaluator := NewPolicyEvaluator()

	// Create temp policy file
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "test-policy.yaml")
	policyContent := `name: test-custom
version: "1.0"
description: Test custom policy
rules:
  protocol:
    minVersion: TLS 1.3
    bannedVersions:
      - TLS 1.0
      - TLS 1.1
  cipher:
    minKeySize: 128
    requireForwardSecrecy: true
`
	if err := os.WriteFile(policyPath, []byte(policyContent), 0644); err != nil {
		t.Fatalf("failed to write test policy: %v", err)
	}

	policy, err := evaluator.LoadPolicy(policyPath)
	if err != nil {
		t.Fatalf("LoadPolicy() error = %v", err)
	}

	if policy.Name != "test-custom" {
		t.Errorf("policy.Name = %s, want test-custom", policy.Name)
	}

	if policy.Rules.Protocol.BannedVersions == nil || len(policy.Rules.Protocol.BannedVersions) != 2 {
		t.Error("policy should have 2 banned protocol versions")
	}
}

func TestPolicyEvaluatorLoadPolicyNotFound(t *testing.T) {
	evaluator := NewPolicyEvaluator()

	_, err := evaluator.LoadPolicy("/nonexistent/path/policy.yaml")
	if err == nil {
		t.Error("LoadPolicy(nonexistent) should return error")
	}
}

func TestPolicyEvaluatorQuantumReady(t *testing.T) {
	evaluator := NewPolicyEvaluator()
	result := createQuantumReadyResult()

	policy, _ := evaluator.GetPolicy("cnsa-2.0-2027")
	policyResult := evaluator.Evaluate(result, policy)

	if policyResult == nil {
		t.Fatal("Evaluate() returned nil")
	}

	// Quantum-ready should have fewer violations
	// (may still have some due to other requirements)
	if len(policyResult.Violations) > 5 {
		t.Errorf("quantum-ready result has too many violations: %d", len(policyResult.Violations))
	}
}
