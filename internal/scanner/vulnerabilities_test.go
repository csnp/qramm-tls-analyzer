package scanner

import (
	"testing"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

func TestContainsAny(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		substrs  []string
		expected bool
	}{
		{"empty string", "", []string{"a"}, false},
		{"empty substrs", "hello", []string{}, false},
		{"single match", "hello world", []string{"world"}, true},
		{"no match", "hello world", []string{"foo"}, false},
		{"multiple substrs first matches", "hello", []string{"ell", "bar"}, true},
		{"multiple substrs second matches", "hello", []string{"foo", "llo"}, true},
		{"case sensitive no match", "Hello", []string{"hello"}, false},
		{"substring at start", "hello", []string{"hel"}, true},
		{"substring at end", "hello", []string{"llo"}, true},
		{"SHA1 in algorithm", "SHA1WithRSA", []string{"SHA1", "MD5"}, true},
		{"SHA256 in algorithm", "SHA256WithRSA", []string{"SHA1", "MD5"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsAny(tt.s, tt.substrs...); got != tt.expected {
				t.Errorf("containsAny(%q, %v) = %v, want %v", tt.s, tt.substrs, got, tt.expected)
			}
		})
	}
}

func TestCheckVulnerabilities(t *testing.T) {
	s := New(nil)

	tests := []struct {
		name       string
		result     *types.ScanResult
		wantVulnID string
	}{
		{
			name: "TLS 1.0 vulnerability",
			result: &types.ScanResult{
				Protocols: []types.Protocol{
					{Version: "TLS 1.0", Supported: true},
				},
			},
			wantVulnID: "TLS10_ENABLED",
		},
		{
			name: "TLS 1.1 vulnerability",
			result: &types.ScanResult{
				Protocols: []types.Protocol{
					{Version: "TLS 1.1", Supported: true},
				},
			},
			wantVulnID: "TLS11_ENABLED",
		},
		{
			name: "SSL 3.0 vulnerability",
			result: &types.ScanResult{
				Protocols: []types.Protocol{
					{Version: "SSL 3.0", Supported: true},
				},
			},
			wantVulnID: "SSL3_ENABLED",
		},
		{
			name: "No TLS 1.3 vulnerability",
			result: &types.ScanResult{
				Protocols: []types.Protocol{
					{Version: "TLS 1.2", Supported: true},
				},
			},
			wantVulnID: "NO_TLS13",
		},
		{
			name: "Expired certificate",
			result: &types.ScanResult{
				Protocols: []types.Protocol{
					{Version: "TLS 1.3", Supported: true},
				},
				Certificate: &types.Certificate{
					Expired: true,
				},
			},
			wantVulnID: "CERT_EXPIRED",
		},
		{
			name: "Expiring certificate",
			result: &types.ScanResult{
				Protocols: []types.Protocol{
					{Version: "TLS 1.3", Supported: true},
				},
				Certificate: &types.Certificate{
					DaysUntilExpiry: 15,
				},
			},
			wantVulnID: "CERT_EXPIRING",
		},
		{
			name: "Weak RSA key",
			result: &types.ScanResult{
				Protocols: []types.Protocol{
					{Version: "TLS 1.3", Supported: true},
				},
				Certificate: &types.Certificate{
					PublicKeyAlgorithm: "RSA",
					PublicKeyBits:      1024,
					DaysUntilExpiry:    365,
				},
			},
			wantVulnID: "CERT_WEAK_KEY",
		},
		{
			name: "Weak signature",
			result: &types.ScanResult{
				Protocols: []types.Protocol{
					{Version: "TLS 1.3", Supported: true},
				},
				Certificate: &types.Certificate{
					SignatureAlgorithm: "SHA1WithRSA",
					DaysUntilExpiry:    365,
				},
			},
			wantVulnID: "CERT_WEAK_SIG",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vulns := s.checkVulnerabilities(tt.result)

			found := false
			for _, v := range vulns {
				if v.ID == tt.wantVulnID {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("expected vulnerability %s not found in results: %v", tt.wantVulnID, vulns)
			}
		})
	}
}

func TestCheckVulnerabilitiesNoFalsePositives(t *testing.T) {
	s := New(nil)

	// Secure configuration
	result := &types.ScanResult{
		Protocols: []types.Protocol{
			{Version: "TLS 1.3", Supported: true},
			{Version: "TLS 1.2", Supported: true},
			{Version: "TLS 1.1", Supported: false},
			{Version: "TLS 1.0", Supported: false},
		},
		CipherSuites: []types.CipherSuite{
			{
				Name:           "TLS_AES_256_GCM_SHA384",
				ForwardSecrecy: true,
				Bits:           256,
			},
		},
		Certificate: &types.Certificate{
			PublicKeyAlgorithm: "ECDSA",
			PublicKeyBits:      256,
			SignatureAlgorithm: "SHA256WithECDSA",
			DaysUntilExpiry:    365,
			Expired:            false,
			IsSelfSigned:       false,
		},
	}

	vulns := s.checkVulnerabilities(result)

	// Should have no critical or high vulnerabilities
	for _, v := range vulns {
		if v.Severity == types.SeverityCritical || v.Severity == types.SeverityHigh {
			t.Errorf("unexpected %s vulnerability in secure config: %s", v.Severity, v.ID)
		}
	}
}
