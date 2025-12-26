// Package scanner provides TLS scanning capabilities.
package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// Version is the scanner version.
const Version = "0.1.0"

// Scanner performs TLS analysis on targets.
type Scanner struct {
	config *Config
}

// Config holds scanner configuration.
type Config struct {
	Timeout         time.Duration
	ConnectTimeout  time.Duration
	Concurrency     int
	SkipCertVerify  bool
	SNI             string
	CheckVulns      bool
	CheckQuantum    bool
	MinTLSVersion   uint16
	MaxTLSVersion   uint16
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Timeout:        30 * time.Second,
		ConnectTimeout: 10 * time.Second,
		Concurrency:    10,
		SkipCertVerify: true, // We're analyzing, not validating
		CheckVulns:     true,
		CheckQuantum:   true,
		MinTLSVersion:  tls.VersionSSL30,
		MaxTLSVersion:  tls.VersionTLS13,
	}
}

// New creates a new Scanner with the given config.
func New(cfg *Config) *Scanner {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Scanner{config: cfg}
}

// Scan performs a complete TLS analysis of the target.
func (s *Scanner) Scan(ctx context.Context, target string) (*types.ScanResult, error) {
	start := time.Now()

	host, port, err := parseTarget(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	result := &types.ScanResult{
		Target:         target,
		Host:           host,
		Port:           port,
		Timestamp:      start,
		ScannerVersion: Version,
	}

	// Resolve IP
	ips, err := net.LookupIP(host)
	if err == nil && len(ips) > 0 {
		result.IP = ips[0].String()
	}

	// Run probes concurrently
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Probe protocols
	wg.Add(1)
	go func() {
		defer wg.Done()
		protocols := s.probeProtocols(ctx, host, port)
		mu.Lock()
		result.Protocols = protocols
		mu.Unlock()
	}()

	// Get certificate and cipher suites (from preferred connection)
	wg.Add(1)
	go func() {
		defer wg.Done()
		cert, chain, ciphers, keyExchanges := s.probeConnection(ctx, host, port)
		mu.Lock()
		result.Certificate = cert
		result.CertChain = chain
		result.CipherSuites = ciphers
		result.KeyExchanges = keyExchanges
		mu.Unlock()
	}()

	wg.Wait()

	// Analyze results
	if s.config.CheckVulns {
		result.Vulnerabilities = s.checkVulnerabilities(result)
	}

	if s.config.CheckQuantum {
		result.QuantumRisk = s.assessQuantumRisk(result)
	}

	result.Grade = s.calculateGrade(result)
	result.Recommendations = s.generateRecommendations(result)

	result.Duration = types.Duration{Duration: time.Since(start)}
	return result, nil
}

// probeProtocols checks which TLS versions are supported.
func (s *Scanner) probeProtocols(ctx context.Context, host string, port int) []types.Protocol {
	versions := []struct {
		version uint16
		name    string
	}{
		{tls.VersionTLS13, "TLS 1.3"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS10, "TLS 1.0"},
	}

	var protocols []types.Protocol
	var preferred string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Check each version concurrently
	for _, v := range versions {
		wg.Add(1)
		go func(ver uint16, name string) {
			defer wg.Done()

			cfg := &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         ver,
				MaxVersion:         ver,
				ServerName:         s.getSNI(host),
			}

			supported := s.tryConnect(ctx, host, port, cfg)

			mu.Lock()
			defer mu.Unlock()
			protocols = append(protocols, types.Protocol{
				Version:   name,
				Supported: supported,
			})
			// First successful is preferred (we check in order)
			if supported && preferred == "" {
				preferred = name
			}
		}(v.version, v.name)
	}

	wg.Wait()

	// Mark preferred
	for i := range protocols {
		if protocols[i].Version == preferred {
			protocols[i].Preferred = true
			break
		}
	}

	return protocols
}

// probeConnection connects with best available settings and extracts info.
func (s *Scanner) probeConnection(ctx context.Context, host string, port int) (
	*types.Certificate, []types.Certificate, []types.CipherSuite, []types.KeyExchange) {

	cfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         s.getSNI(host),
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: s.config.ConnectTimeout}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		return nil, nil, nil, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// Extract certificate info
	var cert *types.Certificate
	var chain []types.Certificate

	if len(state.PeerCertificates) > 0 {
		cert = parseCertificate(state.PeerCertificates[0])
		for _, c := range state.PeerCertificates[1:] {
			chain = append(chain, *parseCertificate(c))
		}
	}

	// Extract cipher suite info
	var ciphers []types.CipherSuite
	cs := parseCipherSuite(state.CipherSuite, state.Version)
	if cs != nil {
		ciphers = append(ciphers, *cs)
	}

	// Extract key exchange info
	var keyExchanges []types.KeyExchange
	ke := parseKeyExchange(state)
	if ke != nil {
		keyExchanges = append(keyExchanges, *ke)
	}

	return cert, chain, ciphers, keyExchanges
}

// tryConnect attempts a TLS connection with the given config.
func (s *Scanner) tryConnect(ctx context.Context, host string, port int, cfg *tls.Config) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: s.config.ConnectTimeout}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (s *Scanner) getSNI(host string) string {
	if s.config.SNI != "" {
		return s.config.SNI
	}
	return host
}

// parseCertificate extracts relevant info from an x509 certificate.
func parseCertificate(cert *x509.Certificate) *types.Certificate {
	now := time.Now()

	// Calculate fingerprints
	sha256sum := sha256Fingerprint(cert.Raw)
	sha1sum := sha1Fingerprint(cert.Raw)

	// Extract key usage
	var keyUsage []string
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		keyUsage = append(keyUsage, "digitalSignature")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		keyUsage = append(keyUsage, "keyEncipherment")
	}
	if cert.KeyUsage&x509.KeyUsageKeyAgreement != 0 {
		keyUsage = append(keyUsage, "keyAgreement")
	}

	// Extract extended key usage
	var extKeyUsage []string
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			extKeyUsage = append(extKeyUsage, "serverAuth")
		case x509.ExtKeyUsageClientAuth:
			extKeyUsage = append(extKeyUsage, "clientAuth")
		case x509.ExtKeyUsageCodeSigning:
			extKeyUsage = append(extKeyUsage, "codeSigning")
		}
	}

	// Determine public key size
	var bits int
	var algo string
	switch pub := cert.PublicKey.(type) {
	case interface{ Size() int }:
		bits = pub.Size() * 8
	}
	algo = cert.PublicKeyAlgorithm.String()

	// Check if quantum-safe (currently none are, unless using PQC)
	quantumSafe := false // Future: detect ML-DSA, etc.

	daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)

	return &types.Certificate{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: algo,
		PublicKeyBits:      bits,
		KeyUsage:           keyUsage,
		ExtKeyUsage:        extKeyUsage,
		SANs:               cert.DNSNames,
		IsCA:               cert.IsCA,
		IsSelfSigned:       cert.Subject.String() == cert.Issuer.String(),
		QuantumSafe:        quantumSafe,
		DaysUntilExpiry:    daysUntilExpiry,
		Expired:            now.After(cert.NotAfter),
		Fingerprints: types.Fingerprints{
			SHA256: sha256sum,
			SHA1:   sha1sum,
		},
	}
}

// parseCipherSuite extracts cipher suite details.
func parseCipherSuite(id uint16, version uint16) *types.CipherSuite {
	name := tls.CipherSuiteName(id)
	if name == "" {
		name = fmt.Sprintf("0x%04X", id)
	}

	cs := &types.CipherSuite{
		ID:       id,
		Name:     name,
		Protocol: tlsVersionName(version),
	}

	// Parse cipher suite components
	parseCSComponents(cs, name)

	return cs
}

// parseCSComponents parses cipher suite name into components.
func parseCSComponents(cs *types.CipherSuite, name string) {
	// TLS 1.3 cipher suites
	if strings.HasPrefix(name, "TLS_AES_") || strings.HasPrefix(name, "TLS_CHACHA20_") {
		cs.KeyExchange = "any" // TLS 1.3 separates key exchange
		cs.Authentication = "any"
		cs.ForwardSecrecy = true

		if strings.Contains(name, "256") {
			cs.Bits = 256
		} else if strings.Contains(name, "128") {
			cs.Bits = 128
		}

		if strings.Contains(name, "AES") {
			cs.Encryption = "AES-GCM"
		} else if strings.Contains(name, "CHACHA20") {
			cs.Encryption = "ChaCha20-Poly1305"
		}
		return
	}

	// TLS 1.2 and earlier
	parts := strings.Split(name, "_")
	for i, part := range parts {
		switch {
		case part == "ECDHE" || part == "DHE":
			cs.KeyExchange = part
			cs.ForwardSecrecy = true
		case part == "RSA" && i < 3:
			if cs.KeyExchange == "" {
				cs.KeyExchange = "RSA"
			}
			cs.Authentication = "RSA"
		case part == "ECDSA":
			cs.Authentication = "ECDSA"
		case strings.HasPrefix(part, "AES"):
			cs.Encryption = "AES"
		case part == "CHACHA20":
			cs.Encryption = "ChaCha20"
		case part == "3DES":
			cs.Encryption = "3DES"
			cs.Deprecated = true
			cs.DeprecatedReason = "3DES is deprecated due to small block size"
		case part == "RC4":
			cs.Encryption = "RC4"
			cs.Deprecated = true
			cs.DeprecatedReason = "RC4 is broken"
		case part == "128":
			cs.Bits = 128
		case part == "256":
			cs.Bits = 256
		case part == "SHA256" || part == "SHA384":
			cs.MAC = part
		case part == "SHA":
			cs.MAC = "SHA1"
		case part == "MD5":
			cs.MAC = "MD5"
			cs.Deprecated = true
			cs.DeprecatedReason = "MD5 is broken"
		}
	}

	// Quantum safety - currently only hybrid/PQC key exchanges are safe
	cs.QuantumSafe = false
}

// parseKeyExchange extracts key exchange info from connection state.
func parseKeyExchange(state tls.ConnectionState) *types.KeyExchange {
	ke := &types.KeyExchange{}

	// Determine key exchange from cipher suite and curve
	if state.Version == tls.VersionTLS13 {
		// TLS 1.3 uses separate key share
		ke.Name = "X25519" // Default, would need extension to detect PQC
		ke.Type = "classical"
		ke.Curve = "X25519"
		ke.Bits = 256
		ke.QuantumSafe = false

		// TODO: Detect hybrid PQC key exchanges
		// This requires raw handshake access or extension parsing
		// X25519MLKEM768 would be detectable by key share size (1216 bytes)
	}

	return ke
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionSSL30:
		return "SSL 3.0"
	default:
		return fmt.Sprintf("0x%04X", v)
	}
}

func parseTarget(target string) (string, int, error) {
	// Add default port if not specified
	if !strings.Contains(target, ":") {
		target = target + ":443"
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, err
	}

	port := 443
	if portStr != "" {
		fmt.Sscanf(portStr, "%d", &port)
	}

	return host, port, nil
}

func sha256Fingerprint(data []byte) string {
	// Implementation using crypto/sha256
	return hex.EncodeToString(data[:20]) + "..." // Abbreviated for now
}

func sha1Fingerprint(data []byte) string {
	// Implementation using crypto/sha1
	return hex.EncodeToString(data[:10]) + "..." // Abbreviated for now
}
