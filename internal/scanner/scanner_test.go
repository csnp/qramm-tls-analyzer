package scanner

import (
	"context"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
	}{
		{
			name:   "nil config uses defaults",
			config: nil,
		},
		{
			name: "custom config",
			config: &Config{
				Timeout:        60 * time.Second,
				ConnectTimeout: 30 * time.Second,
				Concurrency:    5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(tt.config)
			if s == nil {
				t.Error("New returned nil")
			}
			if s.config == nil {
				t.Error("Scanner config is nil")
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", cfg.Timeout)
	}
	if cfg.ConnectTimeout != 10*time.Second {
		t.Errorf("expected connect timeout 10s, got %v", cfg.ConnectTimeout)
	}
	if cfg.Concurrency != 10 {
		t.Errorf("expected concurrency 10, got %d", cfg.Concurrency)
	}
	if !cfg.CheckVulns {
		t.Error("expected CheckVulns to be true")
	}
	if !cfg.CheckQuantum {
		t.Error("expected CheckQuantum to be true")
	}
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		target   string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{"example.com", "example.com", 443, false},
		{"example.com:8443", "example.com", 8443, false},
		{"example.com:443", "example.com", 443, false},
		{"192.168.1.1", "192.168.1.1", 443, false},
		{"192.168.1.1:8080", "192.168.1.1", 8080, false},
		{"[::1]:443", "::1", 443, false},
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			host, port, err := parseTarget(tt.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseTarget() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if host != tt.wantHost {
				t.Errorf("parseTarget() host = %v, want %v", host, tt.wantHost)
			}
			if port != tt.wantPort {
				t.Errorf("parseTarget() port = %v, want %v", port, tt.wantPort)
			}
		})
	}
}

func TestTlsVersionName(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{0x0304, "TLS 1.3"},
		{0x0303, "TLS 1.2"},
		{0x0302, "TLS 1.1"},
		{0x0301, "TLS 1.0"},
		{0x0300, "SSL 3.0"},
		{0x0000, "0x0000"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tlsVersionName(tt.version); got != tt.want {
				t.Errorf("tlsVersionName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetSNI(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		host     string
		expected string
	}{
		{
			name:     "uses host when SNI not set",
			config:   &Config{},
			host:     "example.com",
			expected: "example.com",
		},
		{
			name:     "uses SNI when set",
			config:   &Config{SNI: "custom.example.com"},
			host:     "example.com",
			expected: "custom.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Scanner{config: tt.config}
			if got := s.getSNI(tt.host); got != tt.expected {
				t.Errorf("getSNI() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// Integration test - requires network
func TestScanIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	cfg := DefaultConfig()
	cfg.Timeout = 15 * time.Second
	cfg.ConnectTimeout = 5 * time.Second

	s := New(cfg)
	ctx := context.Background()

	result, err := s.Scan(ctx, "google.com")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Basic checks
	if result.Target != "google.com" {
		t.Errorf("expected target google.com, got %s", result.Target)
	}
	if result.Host != "google.com" {
		t.Errorf("expected host google.com, got %s", result.Host)
	}
	if result.Port != 443 {
		t.Errorf("expected port 443, got %d", result.Port)
	}
	if result.IP == "" {
		t.Error("expected IP to be set")
	}

	// Protocol checks
	if len(result.Protocols) == 0 {
		t.Error("expected protocols to be populated")
	}

	// Google should support TLS 1.3
	hasTLS13 := false
	for _, p := range result.Protocols {
		if p.Version == "TLS 1.3" && p.Supported {
			hasTLS13 = true
			break
		}
	}
	if !hasTLS13 {
		t.Error("expected google.com to support TLS 1.3")
	}

	// Certificate check
	if result.Certificate == nil {
		t.Error("expected certificate to be present")
	} else {
		if result.Certificate.Subject == "" {
			t.Error("expected certificate subject to be set")
		}
		if result.Certificate.Expired {
			t.Error("expected certificate to not be expired")
		}
	}

	// Grade check
	if result.Grade.Letter == "" {
		t.Error("expected grade letter to be set")
	}
	if result.Grade.Score < 0 || result.Grade.Score > 100 {
		t.Errorf("expected grade score 0-100, got %d", result.Grade.Score)
	}

	// Quantum risk check
	if result.QuantumRisk.Level == "" {
		t.Error("expected quantum risk level to be set")
	}
}
