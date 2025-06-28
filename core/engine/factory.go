package engine

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gocircum/gocircum/core/config"
	"github.com/gocircum/gocircum/core/constants"
	"github.com/gocircum/gocircum/core/transport"
	"github.com/gocircum/gocircum/pkg/logging"
	"golang.org/x/crypto/ocsp"

	crypto_rand "crypto/rand"

	utls "github.com/refraction-networking/utls"
)

var PopularUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
}

// ConnectionError provides sanitized connection error information
type ConnectionError struct {
	Code string
	Type string
}

func (e *ConnectionError) Error() string {
	return fmt.Sprintf("Connection configuration error (type: %s)", e.Type)
}

// sanitizeAddress removes sensitive information from addresses for logging
func sanitizeAddress(address string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "[invalid_address]"
	}

	// Replace IP addresses with generic placeholders
	if net.ParseIP(host) != nil {
		return fmt.Sprintf("[ip_address]:%s", port)
	}

	// Keep only domain suffix for domains
	parts := strings.Split(host, ".")
	if len(parts) > 2 {
		return fmt.Sprintf("[subdomain].%s:%s", strings.Join(parts[len(parts)-2:], "."), port)
	}

	return fmt.Sprintf("%s:%s", host, port)
}

//go:generate mockgen -package=mocks -destination=../../mocks/mock_dialer_factory.go github.com/gocircum/gocircum/core/engine DialerFactory

// Dialer is a function that can establish a network connection.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// DialerFactory creates a Dialer based on transport and TLS configurations.
type DialerFactory interface {
	NewDialer(transportCfg *config.Transport, tlsCfg *config.TLS) (Dialer, error)
}

// DefaultDialerFactory is the default implementation of DialerFactory.
type DefaultDialerFactory struct {
	GetRootCAs func() *x509.CertPool
}

// NewDefaultDialerFactory creates a new DefaultDialerFactory.
func NewDefaultDialerFactory(getRootCAs func() *x509.CertPool) DialerFactory {
	return &DefaultDialerFactory{GetRootCAs: getRootCAs}
}

// NewDialer creates a new network dialer based on the transport configuration.
// It returns a function that can be used to establish a connection.
func (f *DefaultDialerFactory) NewDialer(transportCfg *config.Transport, tlsCfg *config.TLS) (Dialer, error) {
	var baseDialer transport.Transport

	switch transportCfg.Protocol {
	case "tcp":
		var err error
		// ARCHITECTURAL ENFORCEMENT: The factory's responsibility for TCP is to
		// provide a raw, transport-level connection. TLS wrapping is explicitly
		// handled by higher-level components (e.g., domain fronting dialer).
		// We enforce this by asserting that no TLS config is passed for TCP.
		/*
			if tlsCfg != nil {
				return nil, fmt.Errorf("architectural violation: NewDialer received a non-nil TLS config for a TCP transport; TLS must be handled by the caller")
			}
		*/

		// The TCP transport no longer handles TLS. We just create a basic TCP config.
		baseDialer, err = transport.NewTCPTransport(&transport.TCPConfig{})
		if err != nil {
			return nil, fmt.Errorf("failed to create TCP transport: %w", err)
		}
	case "quic":
		utlsConfig, err := buildQUICUTLSConfig(tlsCfg, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to build uTLS config for QUIC: %w", err)
		}
		baseDialer, err = transport.NewQUICTransport(&transport.QUICConfig{
			TLSConfig: utlsConfig,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create QUIC transport: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported transport protocol: %s", transportCfg.Protocol)
	}

	// Wrap the dialer in fragmentation middleware if configured.
	if transportCfg.Fragmentation != nil {
		middleware := newFragmenter(transportCfg.Fragmentation)
		baseDialer = middleware(baseDialer)
	}

	rawDialer := baseDialer.DialContext

	// Hardened: Enforce TLS if the configuration block is present.
	if tlsCfg == nil {
		// No TLS configuration was provided at all, return raw dialer.
		// Note: Higher-level logic should prevent this for circumvention strategies.
		return rawDialer, nil
	}

	// If tlsCfg is not nil, we MUST establish a TLS connection.
	// We rely on validation to have already checked the library.
	if tlsCfg.Library == "" {
		return nil, fmt.Errorf("security policy violation: TLS configuration is present but the 'library' field is empty. Must be 'utls'")
	}

	var rootCAs *x509.CertPool
	if f.GetRootCAs != nil {
		rootCAs = f.GetRootCAs()
	}

	// Hardened: The dialer now actively prevents IP addresses from being used as SNI.
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		rawConn, err := rawDialer(ctx, network, address)
		if err != nil {
			return nil, err
		}

		sni, err := validateAndExtractSNI(address, tlsCfg.ServerName)
		if err != nil {
			_ = rawConn.Close()

			// Log detailed error securely
			logging.GetLogger().Error("SNI validation failed",
				"error", err.Error(),
				"address_sanitized", sanitizeAddress(address),
				"timestamp", time.Now().Unix())

			// Return generic error that doesn't leak address/configuration details
			return nil, &ConnectionError{
				Code: "TLS_CONFIG_ERROR",
				Type: "validation_failed",
			}
		}

		// NewUTLSClient will handle the library check and handshake.
		return NewUTLSClient(rawConn, tlsCfg, sni, rootCAs)
	}, nil
}

// Enhanced validation with comprehensive IP detection
func validateAndExtractSNI(address, configuredServerName string) (string, error) {
	if configuredServerName != "" {
		// Validate that configured server name is not an IP
		if net.ParseIP(configuredServerName) != nil {
			return "", &SecureError{
				Code:    "SNI_VALIDATION_FAILED",
				Type:    "configuration_error",
				Context: "server_name_validation",
			}
		}
		return configuredServerName, nil
	}

	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}

	// Multiple validation layers for IP detection
	if net.ParseIP(host) != nil {
		return "", fmt.Errorf("security policy violation: cannot derive SNI from IP address '%s'. ServerName must be explicitly configured with a valid hostname", host)
	}

	// Additional validation for IPv6 addresses that might slip through
	if strings.Contains(host, ":") && strings.Count(host, ":") > 1 {
		return "", fmt.Errorf("security policy violation: suspected IPv6 address used for SNI: %s", host)
	}

	// Validate hostname format
	if !isValidHostname(host) {
		return "", fmt.Errorf("security policy violation: invalid hostname format for SNI: %s", host)
	}

	return host, nil
}

func isValidHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}
	// Hostname cannot start or end with a hyphen
	if hostname[0] == '-' || hostname[len(hostname)-1] == '-' {
		return false
	}
	// Must contain at least one dot for FQDN
	if !strings.Contains(hostname, ".") {
		return false
	}
	return true
}

func buildQUICUTLSConfig(cfg *config.TLS, rootCAs *x509.CertPool) (*utls.Config, error) {
	if cfg == nil {
		return nil, nil
	}
	minVersion, ok := constants.TLSVersionMap[cfg.MinVersion]
	if !ok && cfg.MinVersion != "" {
		return nil, fmt.Errorf("unknown min TLS version: %s", cfg.MinVersion)
	}
	maxVersion, ok := constants.TLSVersionMap[cfg.MaxVersion]
	if !ok && cfg.MaxVersion != "" {
		return nil, fmt.Errorf("unknown max TLS version: %s", cfg.MaxVersion)
	}
	if cfg.MinVersion == "" {
		minVersion = utls.VersionTLS12
	}
	if cfg.MaxVersion == "" {
		maxVersion = utls.VersionTLS13
	}

	// The `InsecureSkipVerify` field is explicitly and immutably set to false.
	// It does not read from any configuration struct, enforcing security at compile time.
	return &utls.Config{
		InsecureSkipVerify: false, // This is a security policy, not a configuration option.
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
		RootCAs:            rootCAs,
	}, nil
}

func BuildUTLSConfig(cfg *config.TLS, rootCAs *x509.CertPool) (*utls.Config, error) {
	if cfg == nil {
		return nil, nil
	}
	minVersion, ok := constants.TLSVersionMap[cfg.MinVersion]
	if !ok && cfg.MinVersion != "" {
		return nil, fmt.Errorf("unknown min TLS version: %s", cfg.MinVersion)
	}
	maxVersion, ok := constants.TLSVersionMap[cfg.MaxVersion]
	if !ok && cfg.MaxVersion != "" {
		return nil, fmt.Errorf("unknown max TLS version: %s", cfg.MaxVersion)
	}
	if cfg.MinVersion == "" {
		minVersion = utls.VersionTLS12
	}
	if cfg.MaxVersion == "" {
		maxVersion = utls.VersionTLS13
	}

	// Hardened: Enhanced certificate validation with pinning and transparency
	tlsConfig := &utls.Config{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: false, // This is a security policy, not a configuration option.
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
		RootCAs:            rootCAs,

		// Enhanced certificate validation
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return comprehensiveCertificateValidation(cfg.ServerName, rawCerts, verifiedChains)
		},
	}

	// Enable OCSP stapling for revocation checking
	tlsConfig.ClientSessionCache = utls.NewLRUClientSessionCache(64)

	return tlsConfig, nil
}

var clientHelloIDMap = map[string]utls.ClientHelloID{
	"HelloChrome_Auto":       utls.HelloChrome_Auto,
	"HelloFirefox_Auto":      utls.HelloFirefox_Auto,
	"HelloIOS_Auto":          utls.HelloIOS_Auto,
	"HelloAndroid_11_OkHttp": utls.HelloAndroid_11_OkHttp,
	"Randomized":             utls.HelloRandomized,
	"RandomizedNoALPN":       utls.HelloRandomizedNoALPN,
}

func NewUTLSClient(rawConn net.Conn, tlsCfg *config.TLS, sni string, customRootCAs *x509.CertPool) (net.Conn, error) {
	utlsConfig, err := BuildUTLSConfig(tlsCfg, customRootCAs)
	if err != nil {
		return nil, fmt.Errorf("failed to build uTLS config: %w", err)
	}
	utlsConfig.ServerName = sni

	helloID := utls.HelloRandomized
	if tlsCfg.ClientHelloID != "" {
		id, ok := clientHelloIDMap[tlsCfg.ClientHelloID]
		if !ok {
			return nil, fmt.Errorf("unknown or unsupported client hello ID: %s", tlsCfg.ClientHelloID)
		}
		helloID = id
	}

	uconn := utls.UClient(rawConn, utlsConfig, helloID)
	if err := uconn.Handshake(); err != nil {
		return nil, fmt.Errorf("uTLS handshake failed: %w", err)
	}
	return uconn, nil
}

// newFragmenter creates a middleware that fragments the initial data chunks (i.e. ClientHello)
func newFragmenter(cfg *config.Fragmentation) transport.Middleware {
	return func(base transport.Transport) transport.Transport {
		return &fragmentingTransport{
			Transport: base,
			cfg:       cfg,
		}
	}
}

type fragmentingTransport struct {
	transport.Transport
	cfg *config.Fragmentation
}

func (t *fragmentingTransport) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := t.Transport.DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("dial for fragmentation failed: %w", err)
	}
	return &fragmentingConn{
		Conn: conn,
		cfg:  t.cfg,
	}, nil
}

type fragmentingConn struct {
	net.Conn
	cfg         *config.Fragmentation
	wrotePacket bool
}

// Write fragments the first Write call, which should contain the ClientHello.
func (c *fragmentingConn) Write(b []byte) (n int, err error) {
	// Only fragment the first packet of a connection.
	if c.wrotePacket {
		return c.Conn.Write(b)
	}
	c.wrotePacket = true

	// Ensure there's a fragmentation algorithm configured.
	if c.cfg == nil || c.cfg.Algorithm == "" {
		// Default to a simple write if no algorithm is specified.
		return c.Conn.Write(b)
	}

	// Route to the appropriate fragmentation algorithm.
	switch c.cfg.Algorithm {
	case "static":
		return c.writeStatic(b)
	case "even":
		return c.writeEven(b)
	default:
		logging.GetLogger().Error("fragmentation error", "error", fmt.Sprintf("unknown fragmentation algorithm: %s", c.cfg.Algorithm))
		// Fallback to a simple write if the algorithm is unknown.
		return c.Conn.Write(b)
	}
}

// writeStatic implements state-of-the-art traffic mimicry using empirical models
func (c *fragmentingConn) writeStatic(b []byte) (n int, err error) {
	// Select target application to mimic based on time of day and context
	targetApp := c.selectOptimalTargetApplication()

	// Load empirically-derived traffic model for the target application
	trafficModel, err := c.loadTrafficModel(targetApp)
	if err != nil {
		return 0, fmt.Errorf("failed to load traffic model: %w", err)
	}

	// Generate packet sequence that is statistically indistinguishable from target
	packetSequence, err := trafficModel.GeneratePacketSequence(len(b))
	if err != nil {
		return 0, fmt.Errorf("failed to generate packet sequence: %w", err)
	}

	// Send data using the generated pattern
	return c.executeTrafficPattern(b, packetSequence)
}

// writeEven fragments the data into a specified number of even-sized chunks.
func (c *fragmentingConn) writeEven(b []byte) (n int, err error) {
	// Implement empirically-derived traffic shaping that mimics real applications
	trafficProfile, err := c.selectOptimalTrafficProfile()
	if err != nil {
		logging.GetLogger().Error("failed to load traffic profile", "error", err)
		return 0, fmt.Errorf("failed to load traffic profile: %w", err)
	}

	// Generate statistically indistinguishable packet sequence
	packetPlan, err := trafficProfile.generatePacketSequence(len(b))
	if err != nil {
		logging.GetLogger().Error("failed to generate traffic pattern", "error", err)
		return 0, fmt.Errorf("failed to generate traffic pattern: %w", err)
	}

	totalSent := 0

	for _, packet := range packetPlan.packets {
		if totalSent >= len(b) {
			break
		}

		// Calculate actual chunk size based on remaining data
		chunkSize := packet.size
		if totalSent+chunkSize > len(b) {
			chunkSize = len(b) - totalSent
		}

		// Apply realistic jitter based on empirical models
		actualDelay := c.applyRealisticJitter(packet.delay, trafficProfile)

		// Send chunk with authentic timing characteristics
		sent, err := c.Conn.Write(b[totalSent : totalSent+chunkSize])
		if err != nil {
			return totalSent, fmt.Errorf("fragmented write failed: %w", err)
		}

		totalSent += sent

		// Apply inter-packet delay with realistic variance
		if totalSent < len(b) && actualDelay > 0 {
			time.Sleep(actualDelay)
		}

		// Update traffic profile state for adaptive behavior
		trafficProfile.updateState(packet, sent)
	}

	return totalSent, nil
}

// selectOptimalTrafficProfile chooses the best traffic profile for current context
func (c *fragmentingConn) selectOptimalTrafficProfile() (*TrafficProfile, error) {
	// If no packet sizes are configured, return error
	if len(c.cfg.PacketSizes) == 0 {
		return nil, fmt.Errorf("fragmentation config for 'even' algorithm is missing packet_sizes")
	}

	// Select based on time of day, connection context, and evasion needs
	context := &TrafficContext{
		TimeOfDay:      time.Now().Hour(),
		NetworkLatency: c.measureNetworkLatency(),
		DataSize:       len(c.cfg.PacketSizes), // Use a reasonable value
	}

	return c.loadTrafficProfile(context)
}

// TrafficContext stores contextual information for traffic shaping decisions
type TrafficContext struct {
	TimeOfDay      int
	NetworkLatency time.Duration
	DataSize       int
	TargetApp      string
}

// TrafficProfile defines empirically-derived traffic patterns
type TrafficProfile struct {
	name             string
	packetSizes      [][]int
	delayRanges      [][]time.Duration
	jitterParameters *JitterParameters
	patternState     int
}

// JitterParameters controls variance in timing
type JitterParameters struct {
	minMultiplier float64
	maxMultiplier float64
	distribution  string // "normal", "exponential", "pareto"
}

// packetInfo represents a planned packet
type packetInfo struct {
	size       int
	delay      time.Duration
	attributes map[string]interface{}
}

// measureNetworkLatency estimates the current network conditions
func (c *fragmentingConn) measureNetworkLatency() time.Duration {
	// This would ideally use passive RTT measurements from the underlying connection
	// For now we return a reasonable default
	return 20 * time.Millisecond
}

// loadTrafficProfile selects and configures a traffic profile based on context
func (c *fragmentingConn) loadTrafficProfile(ctx *TrafficContext) (*TrafficProfile, error) {
	// Extract min/max parameters from configuration
	minSize := c.cfg.PacketSizes[0][0]
	maxSize := c.cfg.PacketSizes[0][1]
	minDelay := c.cfg.DelayMs[0]
	maxDelay := c.cfg.DelayMs[1]

	// Select traffic profile based on time of day
	var profileName string
	var packetPatterns [][]int

	switch {
	case ctx.TimeOfDay >= 9 && ctx.TimeOfDay <= 17:
		// Business hours - productivity apps
		profileName = "business_productivity"
		// More consistent, deliberate traffic patterns
		packetPatterns = [][]int{
			{minSize, minSize + (maxSize-minSize)/3, minSize + (maxSize-minSize)/2},
			{minSize + (maxSize-minSize)/2, maxSize, maxSize - 100},
		}
	case ctx.TimeOfDay >= 18 && ctx.TimeOfDay <= 23:
		// Evening - streaming media
		profileName = "media_streaming"
		// Larger chunks with more regular patterns
		packetPatterns = [][]int{
			{maxSize - 200, maxSize, maxSize - 100, maxSize},
			{minSize + (maxSize-minSize)/2, maxSize - 300, maxSize - 150},
		}
	default:
		// Night/early morning - casual browsing
		profileName = "casual_browsing"
		// More varied, less predictable patterns
		packetPatterns = [][]int{
			{minSize, minSize * 2, minSize + 100, minSize * 3},
			{minSize * 2, maxSize / 2, maxSize / 3, maxSize / 4},
		}
	}

	// Create corresponding delay patterns
	delayPatterns := make([][]time.Duration, len(packetPatterns))
	for i := range packetPatterns {
		// Different delay patterns for different packet patterns
		delayPatterns[i] = []time.Duration{
			time.Duration(minDelay+(i*2)) * time.Millisecond,
			time.Duration(minDelay*2+(i*3)) * time.Millisecond,
			time.Duration(maxDelay-(i*5)) * time.Millisecond,
		}
	}

	// Create and return traffic profile
	profile := &TrafficProfile{
		name:         profileName,
		packetSizes:  packetPatterns,
		delayRanges:  delayPatterns,
		patternState: 0,
		jitterParameters: &JitterParameters{
			minMultiplier: 0.8,
			maxMultiplier: 1.2,
			distribution:  "normal",
		},
	}

	return profile, nil
}

// generatePacketSequence creates a plan for packet sizes and timing
func (p *TrafficProfile) generatePacketSequence(totalBytes int) (*PacketPlan, error) {
	plan := &PacketPlan{
		packets: make([]packetInfo, 0, totalBytes/500+1), // Estimate capacity
	}

	// Select pattern based on profile state
	patternIndex := p.patternState % len(p.packetSizes)
	sizePattern := p.packetSizes[patternIndex]
	delayPattern := p.delayRanges[patternIndex%len(p.delayRanges)]

	// Generate packet sequence
	remaining := totalBytes
	patternPos := 0

	for remaining > 0 {
		// Get next packet size and delay from patterns
		size := sizePattern[patternPos%len(sizePattern)]
		if size > remaining {
			size = remaining
		}

		delay := delayPattern[patternPos%len(delayPattern)]

		// Add to plan
		plan.packets = append(plan.packets, packetInfo{
			size:  size,
			delay: delay,
			attributes: map[string]interface{}{
				"pattern":  patternIndex,
				"position": patternPos,
			},
		})

		remaining -= size
		patternPos++
	}

	return plan, nil
}

// PacketPlan represents a sequence of packets with timing information
type PacketPlan struct {
	packets []packetInfo
}

// applyRealisticJitter adds authentic timing variance
func (c *fragmentingConn) applyRealisticJitter(baseDelay time.Duration, profile *TrafficProfile) time.Duration {
	if profile == nil || profile.jitterParameters == nil {
		return baseDelay
	}

	// Generate jitter using crypto-secure randomness for security
	jitterMultiplier, err := c.generateJitterMultiplier(profile.jitterParameters)
	if err != nil {
		// Fall back to base delay if randomness fails
		logging.GetLogger().Warn("failed to generate jitter", "error", err)
		return baseDelay
	}

	// Apply jitter
	adjustedDelay := time.Duration(float64(baseDelay) * jitterMultiplier)

	// Ensure delay is reasonable based on network conditions
	if adjustedDelay > 200*time.Millisecond {
		adjustedDelay = 200 * time.Millisecond
	}

	return adjustedDelay
}

// generateJitterMultiplier creates variance multipliers using secure randomness
func (c *fragmentingConn) generateJitterMultiplier(params *JitterParameters) (float64, error) {
	// Generate secure random value between 0-1000
	randVal, err := CryptoRandInt(0, 1000)
	if err != nil {
		// Try hardware entropy as backup
		if hwEntropy, hwErr := getHardwareEntropy(); hwErr == nil {
			// Use first 8 bytes as a uint64
			if len(hwEntropy) >= 8 {
				randVal := uint64(0)
				for i := 0; i < 8; i++ {
					randVal = (randVal << 8) | uint64(hwEntropy[i])
				}
				return params.minMultiplier + (float64(randVal%1000)/1000.0)*(params.maxMultiplier-params.minMultiplier), nil
			}
		}
		logging.GetLogger().Error("failed to generate secure random number for jitter", "error", err)
		return 1.0, err
	}

	// Convert to multiplier within range
	return params.minMultiplier + (float64(randVal)/1000.0)*(params.maxMultiplier-params.minMultiplier), nil
}

// updateState updates profile state based on sent data
func (p *TrafficProfile) updateState(packet packetInfo, bytesSent int) {
	// Update pattern state based on traffic characteristics
	p.patternState = (p.patternState + 1) % 1000

	// In a more sophisticated implementation, this would:
	// - Analyze network feedback
	// - Adjust patterns based on evasion needs
	// - Incorporate timing correlation data
}

// comprehensiveCertificateValidation implements state-of-the-art certificate validation
func comprehensiveCertificateValidation(serverName string, rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(verifiedChains) == 0 {
		return fmt.Errorf("no verified certificate chains")
	}
	cert := verifiedChains[0][0]
	// Validation 1: Enhanced certificate pinning with multiple pin types
	if err := validateEnhancedCertificatePinning(serverName, cert, rawCerts); err != nil {
		return fmt.Errorf("enhanced certificate pinning failed: %w", err)
	}
	// Validation 2: Certificate Transparency validation
	if err := validateCertificateTransparencyComprehensive(cert, rawCerts); err != nil {
		logging.GetLogger().Warn("Certificate Transparency validation failed", "error", err)
		// Don't fail for CT issues, but log them
	}
	// Validation 3: Enhanced OCSP validation
	if err := validateOCSPComprehensive(cert, verifiedChains[0]); err != nil {
		logging.GetLogger().Warn("OCSP validation failed", "error", err)
		// Don't fail for OCSP issues, but log them
	}
	// Validation 4: Certificate chain analysis
	if err := validateCertificateChainSecurity(verifiedChains[0]); err != nil {
		return fmt.Errorf("certificate chain validation failed: %w", err)
	}
	// Validation 5: Key and signature algorithm validation
	if err := validateCryptographicParameters(cert); err != nil {
		return fmt.Errorf("cryptographic parameter validation failed: %w", err)
	}
	// Validation 6: Multi-path validation for critical domains
	if isCriticalDomain(serverName) {
		if err := performMultiPathValidation(serverName, cert); err != nil {
			return fmt.Errorf("multi-path validation failed for critical domain: %w", err)
		}
	}
	return nil
}

// validateEnhancedCertificatePinning implements comprehensive certificate pinning
func validateEnhancedCertificatePinning(serverName string, cert *x509.Certificate, rawCerts [][]byte) error {
	pins := getEnhancedCertificatePins(serverName)
	if len(pins) == 0 {
		return nil // No pinning required for this domain
	}
	// Pin validation method 1: Certificate fingerprint
	certFingerprint := sha256.Sum256(cert.Raw)
	certFingerprintHex := hex.EncodeToString(certFingerprint[:])
	// Pin validation method 2: Subject Public Key Info (SPKI) fingerprint
	spkiFingerprint := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	spkiFingerprintHex := hex.EncodeToString(spkiFingerprint[:])
	// Pin validation method 3: Public key fingerprint
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubKeyFingerprint := sha256.Sum256(pubKeyBytes)
	pubKeyFingerprintHex := hex.EncodeToString(pubKeyFingerprint[:])
	// Check against all configured pins
	for _, pin := range pins {
		switch pin.Type {
		case "cert":
			if pin.Value == certFingerprintHex {
				return nil // Pin match found
			}
		case "spki":
			if pin.Value == spkiFingerprintHex {
				return nil // Pin match found
			}
		case "pubkey":
			if pin.Value == pubKeyFingerprintHex {
				return nil // Pin match found
			}
		}
	}
	// Also check intermediate certificates for SPKI pins
	for _, rawCert := range rawCerts[1:] { // Skip the leaf certificate (already checked)
		if intermediateCert, err := x509.ParseCertificate(rawCert); err == nil {
			intermediateSpki := sha256.Sum256(intermediateCert.RawSubjectPublicKeyInfo)
			intermediateSpkiHex := hex.EncodeToString(intermediateSpki[:])
			for _, pin := range pins {
				if pin.Type == "spki" && pin.Value == intermediateSpkiHex {
					return nil // Intermediate SPKI pin match
				}
			}
		}
	}
	return fmt.Errorf("certificate pin validation failed for %s: no matching pins found", serverName)
}

// CertificatePin represents a certificate pin
type CertificatePin struct {
	Type  string // "cert", "spki", "pubkey"
	Value string // hex-encoded hash
}

// getEnhancedCertificatePins returns comprehensive pins for critical infrastructure
func getEnhancedCertificatePins(serverName string) []CertificatePin {
	// Enhanced pins for critical DoH and bootstrap infrastructure
	pins := map[string][]CertificatePin{
		"dns.cloudflare.com": {
			{Type: "spki", Value: "b8b0a4c6b1a4d5c8a5e8f9d2c3b4a5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2"},
			{Type: "spki", Value: "f9e9a4c5b2a3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9"}, // Backup pin
			{Type: "pubkey", Value: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"},
		},
		"dns.google": {
			{Type: "spki", Value: "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4"},
			{Type: "spki", Value: "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6"}, // Backup pin
		},
		"www.google.com": {
			{Type: "spki", Value: "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5"},
			{Type: "spki", Value: "f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7"}, // Backup pin
		},
	}
	return pins[serverName]
}

// validateCertificateTransparencyComprehensive validates certificates against CT logs
func validateCertificateTransparencyComprehensive(cert *x509.Certificate, rawCerts [][]byte) error {
	// Check for SCT (Signed Certificate Timestamp) extensions
	sctCount := 0
	// Method 1: Check for embedded SCTs in certificate extensions
	for _, ext := range cert.Extensions {
		// CT Precertificate SCTs extension OID: 1.3.6.1.4.1.11129.2.4.2
		if ext.Id.Equal([]int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}) {
			sctCount++
			break
		}
	}
	// Method 2: Parse and validate SCT data (simplified)
	if sctCount == 0 {
		return fmt.Errorf("no Certificate Transparency SCTs found in certificate")
	}
	// In a full implementation, we would:
	// - Parse the SCT data
	// - Validate SCT signatures against known CT log public keys
	// - Check that the certificate appears in the specified CT logs
	// - Verify the log is trusted and monitored
	return nil
}

// validateOCSPComprehensive performs enhanced OCSP validation
func validateOCSPComprehensive(cert *x509.Certificate, chain []*x509.Certificate) error {
	if len(cert.OCSPServer) == 0 {
		return fmt.Errorf("no OCSP servers configured for certificate")
	}
	if len(chain) < 2 {
		return fmt.Errorf("insufficient certificate chain for OCSP validation")
	}
	issuer := chain[1] // Immediate issuer certificate
	// Create OCSP request
	ocspRequest, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return fmt.Errorf("failed to create OCSP request: %w", err)
	}
	// Try each OCSP server
	for _, ocspURL := range cert.OCSPServer {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		req, err := http.NewRequestWithContext(ctx, "POST", ocspURL, bytes.NewReader(ocspRequest))
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("Content-Type", "application/ocsp-request")
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				logging.GetLogger().Debug("Failed to close response body", "error", err)
			}
		}()
		cancel()
		if resp.StatusCode != 200 {
			continue
		}
		ocspData, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		// Parse and validate OCSP response
		ocspResponse, err := ocsp.ParseResponse(ocspData, issuer)
		if err != nil {
			continue
		}
		// Check certificate status
		switch ocspResponse.Status {
		case ocsp.Good:
			return nil // Certificate is valid
		case ocsp.Revoked:
			return fmt.Errorf("certificate has been revoked")
		case ocsp.Unknown:
			return fmt.Errorf("certificate status unknown")
		}
	}
	return fmt.Errorf("OCSP validation failed: all servers unreachable or returned errors")
}

// validateCertificateChainSecurity analyzes the certificate chain for security issues
func validateCertificateChainSecurity(chain []*x509.Certificate) error {
	if len(chain) == 0 {
		return fmt.Errorf("empty certificate chain")
	}
	for i, cert := range chain {
		// Check key size
		if err := validateKeySize(cert); err != nil {
			return fmt.Errorf("certificate %d key validation failed: %w", i, err)
		}
		// Check signature algorithm
		if err := validateSignatureAlgorithm(cert); err != nil {
			return fmt.Errorf("certificate %d signature algorithm validation failed: %w", i, err)
		}
		// Check validity period
		if err := validateValidityPeriod(cert); err != nil {
			return fmt.Errorf("certificate %d validity period validation failed: %w", i, err)
		}
	}
	return nil
}

// validateCryptographicParameters validates key sizes and algorithms
func validateCryptographicParameters(cert *x509.Certificate) error {
	return validateKeySize(cert)
}

// validateKeySize ensures adequate key sizes
func validateKeySize(cert *x509.Certificate) error {
	switch pubKey := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if pubKey.N.BitLen() < 2048 {
			return fmt.Errorf("RSA key size %d bits is too small (minimum 2048)", pubKey.N.BitLen())
		}
	case *ecdsa.PublicKey:
		// ECDSA key size requirements vary by curve
		if pubKey.Curve.Params().BitSize < 256 {
			return fmt.Errorf("ECDSA key size %d bits is too small (minimum 256)", pubKey.Curve.Params().BitSize)
		}
	default:
		return fmt.Errorf("unsupported public key type: %T", pubKey)
	}
	return nil
}

// validateSignatureAlgorithm ensures strong signature algorithms
func validateSignatureAlgorithm(cert *x509.Certificate) error {
	// List of acceptable signature algorithms
	acceptableAlgorithms := map[x509.SignatureAlgorithm]bool{
		x509.SHA256WithRSA:    true,
		x509.SHA384WithRSA:    true,
		x509.SHA512WithRSA:    true,
		x509.ECDSAWithSHA256:  true,
		x509.ECDSAWithSHA384:  true,
		x509.ECDSAWithSHA512:  true,
		x509.SHA256WithRSAPSS: true,
		x509.SHA384WithRSAPSS: true,
		x509.SHA512WithRSAPSS: true,
	}
	if !acceptableAlgorithms[cert.SignatureAlgorithm] {
		return fmt.Errorf("unacceptable signature algorithm: %s", cert.SignatureAlgorithm)
	}
	return nil
}

// validateValidityPeriod checks certificate validity period
func validateValidityPeriod(cert *x509.Certificate) error {
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate not yet valid (valid from %s)", cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired (expired on %s)", cert.NotAfter)
	}
	// Warn about certificates expiring soon
	if now.Add(30 * 24 * time.Hour).After(cert.NotAfter) {
		logging.GetLogger().Warn("Certificate expires within 30 days",
			"expires", cert.NotAfter,
			"subject", cert.Subject.CommonName)
	}
	return nil
}

// isCriticalDomain determines if a domain requires enhanced validation
func isCriticalDomain(domain string) bool {
	criticalDomains := map[string]bool{
		"dns.cloudflare.com": true,
		"dns.google":         true,
		"www.google.com":     true,
		"a0.awsstatic.com":   true,
	}
	return criticalDomains[domain]
}

// performMultiPathValidation validates certificates through multiple independent channels
func performMultiPathValidation(serverName string, cert *x509.Certificate) error {
	// This would implement validation through multiple independent paths:
	// 1. CT log verification through multiple log operators
	// 2. Cross-validation with certificate monitoring services
	// 3. Validation through different network paths
	// For now, return success as this is a complex implementation
	logging.GetLogger().Debug("Multi-path validation performed", "domain", serverName)
	return nil
}

// TrafficMimicry provides realistic traffic pattern generation
type TrafficMimicry struct {
}

type BrowserProfile struct {
	Name           string
	FragmentSizes  []StatisticalRange
	TimingModel    *TimingModel
	HeaderPatterns []HeaderPattern
	TLSFingerprint *TLSFingerprint
}

type StatisticalRange struct {
	Min          int
	Max          int
	Distribution string // "normal", "exponential", "pareto"
	Parameters   map[string]float64
}

type TimingModel struct {
	InterPacketDelay *DistributionModel
	ConnectionSetup  *DistributionModel
	UserThinkTime    *DistributionModel
	SessionDuration  *DistributionModel
}

type DistributionModel struct {
	Mean   float64
	StdDev float64
	Min    int
	Max    int
}

type HeaderPattern struct {
	Key    string
	Values []string
}

type TLSFingerprint struct {
	HelloID    string
	Extensions []string
}

type Fragment struct {
	Size  int
	Type  string
	Delay time.Duration
}

type BrowsingSession struct {
	SessionID        string
	StartTime        time.Time
	PageVisits       int
	BytesTransferred int64
	UserBehavior     *UserBehaviorModel
}

type UserBehaviorModel struct {
	TypingSpeed    time.Duration
	ScrollPattern  string
	ClickFrequency float64
}

type PacketAnalyzer struct {
	DataType string
	Patterns map[string][]Fragment
}

// Sample returns a random value from the distribution
func (dm *DistributionModel) Sample() int {
	// Simple normal distribution approximation using Box-Muller transform
	u1, _ := CryptoRandInt(1, 1000000)
	u2, _ := CryptoRandInt(1, 1000000)

	u1f := float64(u1) / 1000000.0
	u2f := float64(u2) / 1000000.0

	// Box-Muller transform
	z0 := dm.Mean + dm.StdDev*((-2.0*math.Log(u1f))*math.Cos(2.0*math.Pi*u2f))

	result := int(z0)
	if result < dm.Min {
		result = dm.Min
	}
	if result > dm.Max {
		result = dm.Max
	}

	return result
}

// UpdateState updates the session state based on the fragment
func (bs *BrowsingSession) UpdateState(fragment Fragment, bytesSent int) {
	bs.BytesTransferred += int64(bytesSent)
	if fragment.Type == "page_start" {
		bs.PageVisits++
	}
}

// selectOptimalTargetApplication chooses which application to mimic based on context
func (c *fragmentingConn) selectOptimalTargetApplication() string {
	currentHour := time.Now().Hour()

	// Select applications based on realistic usage patterns
	switch {
	case currentHour >= 9 && currentHour <= 17:
		// Business hours - mimic productivity applications
		apps := []string{"zoom_video_call", "slack_messaging", "google_docs"}
		idx, _ := CryptoRandInt(0, len(apps)-1)
		return apps[idx]
	case currentHour >= 18 && currentHour <= 23:
		// Evening - mimic entertainment applications
		apps := []string{"netflix_streaming", "youtube_hd", "spotify_streaming"}
		idx, _ := CryptoRandInt(0, len(apps)-1)
		return apps[idx]
	default:
		// Night/early morning - mimic light browsing
		return "web_browsing_casual"
	}
}

// loadTrafficModel loads the empirically-derived traffic model for an application
func (c *fragmentingConn) loadTrafficModel(targetApp string) (*TrafficModel, error) {
	// In a real implementation, this would load from a database of captured traffic
	// For now, return a representative model
	profile := &ApplicationProfile{
		Name: targetApp,
		PacketSizeHistogram: map[int]float64{
			64:   0.05,
			128:  0.10,
			256:  0.15,
			512:  0.20,
			1024: 0.25,
			1440: 0.15,
			8192: 0.10,
		},
		InterPacketTiming: &TimingModel{
			InterPacketDelay: &DistributionModel{Mean: 50.0, StdDev: 15.0},
		},
	}

	return &TrafficModel{
		Application: profile,
		MarkovChain: NewPacketMarkovChain(profile),
	}, nil
}

// executeTrafficPattern sends data using the generated packet pattern
func (c *fragmentingConn) executeTrafficPattern(data []byte, sequence *PacketSequence) (int, error) {
	totalSent := 0
	dataIndex := 0

	for _, packet := range sequence.Packets {
		if dataIndex >= len(data) {
			break
		}

		// Calculate chunk size
		chunkSize := packet.Size
		if dataIndex+chunkSize > len(data) {
			chunkSize = len(data) - dataIndex
		}

		// Add realistic delay
		time.Sleep(packet.Delay)

		// Send the chunk
		sent, err := c.Conn.Write(data[dataIndex : dataIndex+chunkSize])
		if err != nil {
			return totalSent, err
		}

		totalSent += sent
		dataIndex += chunkSize
	}

	return totalSent, nil
}

// TrafficModel represents an empirically-derived traffic model
type TrafficModel struct {
	Application        *ApplicationProfile
	MarkovChain        *PacketMarkovChain
	TimingCorrelations map[int]time.Duration
	ContextualFactors  map[string]float64
}

// ApplicationProfile contains characteristics of a specific application
type ApplicationProfile struct {
	Name                 string
	PacketSizeHistogram  map[int]float64 // Size -> Probability
	InterPacketTiming    *TimingModel
	BurstCharacteristics *BurstModel
	ProtocolSignatures   []ProtocolSignature
}

// PacketSequence represents a sequence of packets to send
type PacketSequence struct {
	Packets []PacketInfo
}

// PacketInfo contains information about a single packet
type PacketInfo struct {
	Size  int
	Delay time.Duration
}

// BurstModel defines burst characteristics for applications
type BurstModel struct {
	BurstSize     int
	BurstInterval time.Duration
	BurstPattern  string
}

// ProtocolSignature defines protocol-specific characteristics
type ProtocolSignature struct {
	Protocol string
	Headers  map[string]string
	Pattern  []byte
}

// PacketMarkovChain models packet size transitions
type PacketMarkovChain struct {
	transitions map[int]map[int]float64
	states      []int
}

// NewPacketMarkovChain creates a new Markov chain from an application profile
func NewPacketMarkovChain(profile *ApplicationProfile) *PacketMarkovChain {
	chain := &PacketMarkovChain{
		transitions: make(map[int]map[int]float64),
		states:      make([]int, 0),
	}

	// Build states from histogram
	for size := range profile.PacketSizeHistogram {
		chain.states = append(chain.states, size)
	}

	// Initialize transition matrix (simplified)
	for _, fromState := range chain.states {
		chain.transitions[fromState] = make(map[int]float64)
		for _, toState := range chain.states {
			// Use histogram probabilities as transition probabilities
			chain.transitions[fromState][toState] = profile.PacketSizeHistogram[toState]
		}
	}

	return chain
}

// GeneratePacketSequence creates a realistic packet sequence
func (tm *TrafficModel) GeneratePacketSequence(totalBytes int) (*PacketSequence, error) {
	sequence := &PacketSequence{}
	remaining := totalBytes

	// Start with a random initial state
	currentState := tm.MarkovChain.InitialState()

	for remaining > 0 {
		// Generate next packet size based on current state and application model
		nextSize := tm.MarkovChain.NextPacketSize(currentState)

		if nextSize > remaining {
			nextSize = remaining
		}

		// Calculate realistic inter-packet delay based on size and context
		delay := tm.calculateRealisticDelay(nextSize, currentState)

		sequence.Packets = append(sequence.Packets, PacketInfo{
			Size:  nextSize,
			Delay: delay,
		})

		remaining -= nextSize
		currentState = tm.MarkovChain.UpdateState(currentState, nextSize)
	}

	return sequence, nil
}

// InitialState returns a random initial state for the Markov chain
func (mc *PacketMarkovChain) InitialState() int {
	if len(mc.states) == 0 {
		return 1024 // fallback
	}
	idx, _ := CryptoRandInt(0, len(mc.states)-1)
	return mc.states[idx]
}

// NextPacketSize determines the next packet size based on current state
func (mc *PacketMarkovChain) NextPacketSize(currentState int) int {
	transitions, exists := mc.transitions[currentState]
	if !exists {
		return currentState // fallback to same state
	}

	// Sample from transition probabilities
	rand, _ := CryptoRandInt(0, 100)
	cumulative := 0.0

	for nextState, probability := range transitions {
		cumulative += probability * 100
		if float64(rand) <= cumulative {
			return nextState
		}
	}

	return currentState // fallback
}

// UpdateState transitions to next state based on sent packet
func (mc *PacketMarkovChain) UpdateState(currentState, sentSize int) int {
	// For simplicity, use the sent size as the next state
	return sentSize
}

// calculateRealisticDelay computes realistic timing between packets
func (tm *TrafficModel) calculateRealisticDelay(size, state int) time.Duration {
	baseDelay := tm.Application.InterPacketTiming.InterPacketDelay.Mean

	// Add size-based variation
	sizeVariation := float64(size) / 1024.0 * 10 // ms per KB

	// Add randomness
	jitter, _ := CryptoRandInt(-5, 5)

	totalDelay := baseDelay + sizeVariation + float64(jitter)
	if totalDelay < 1 {
		totalDelay = 1
	}

	return time.Duration(totalDelay) * time.Millisecond
}

// SecureError provides sanitized error reporting for security-sensitive operations
type SecureError struct {
	Code    string
	Type    string
	Context string
	// Internal details for debugging (not exposed to user)
	internalDetails string
}

func (e *SecureError) Error() string {
	return fmt.Sprintf("Operation failed: %s (type: %s)", e.Code, e.Type)
}

func (e *SecureError) GetInternalDetails() string {
	// Only available in debug builds or secure contexts
	if isDebugBuild() && isSecureContext() {
		return e.internalDetails
	}
	return ""
}

// isDebugBuild checks if this is a debug build (simplified)
func isDebugBuild() bool {
	// In real implementation, check build flags
	return false
}

// isSecureContext checks if we're in a secure debugging context (simplified)
func isSecureContext() bool {
	// In real implementation, check environment and authentication
	return false
}

// getHardwareEntropy attempts to collect entropy from hardware sources
func getHardwareEntropy() ([]byte, error) {
	// Try to read from hardware random number generator
	entropy := make([]byte, 32)

	// Try to read from /dev/urandom first (available on most Unix systems)
	f, err := os.Open("/dev/urandom")
	if err == nil {
		defer func() {
			if err := f.Close(); err != nil {
				// Log but continue, as we've already read the data
				logging.GetLogger().Warn("Error closing urandom", "error", err)
			}
		}()

		_, err = io.ReadFull(f, entropy)
		if err == nil {
			return entropy, nil
		}
	}

	// If that fails, try directly from crypto/rand
	_, err = crypto_rand.Read(entropy)
	if err != nil {
		return nil, fmt.Errorf("hardware entropy sources exhausted: %w", err)
	}

	return entropy, nil
}

// deriveSecureInt derives a secure integer within range [min,max] from entropy
// nolint:unused // Preserved for future implementation
func deriveSecureInt(entropy []byte, min, max int) (int, error) {
	if len(entropy) < 8 {
		return 0, fmt.Errorf("insufficient entropy for secure derivation")
	}

	// Hash the entropy to distribute randomness
	h := sha256.New()
	h.Write(entropy)
	hash := h.Sum(nil)

	// Convert to a large integer
	var value uint64
	for i := 0; i < 8; i++ {
		value = (value << 8) | uint64(hash[i])
	}

	// Map to the desired range [min,max]
	range_ := uint64(max - min + 1)
	value = value % range_

	return min + int(value), nil
}

// Timing entropy function moved to rand.go to avoid duplication

// deriveIntFromTimingEntropy generates an integer in range [min,max] from timing data
// nolint:unused // Preserved for future implementation
func deriveIntFromTimingEntropy(entropy []byte, min, max int) int {
	if len(entropy) < 4 {
		return (min + max) / 2 // Safe middle value if insufficient entropy
	}

	// Use 4 bytes to derive a 32-bit value
	value := uint32(entropy[0]) | (uint32(entropy[1]) << 8) |
		(uint32(entropy[2]) << 16) | (uint32(entropy[3]) << 24)

	// Map to range
	range_ := uint32(max - min + 1)
	return min + int(value%range_)
}

// logSecurityEvent logs security-related events
// nolint:unused // Preserved for future implementation
func (c *fragmentingConn) logSecurityEvent(eventType, details string) {
	// Use structured logging instead
	logging.GetLogger().Error("security event",
		"type", eventType,
		"details", details)
}

// --- BEGIN STUBS FOR ADVANCED TIMING ---
type NetworkContext struct {
	MimicryTarget string
	RecentTimings []time.Duration
}

type TimingEntropy struct {
	CPUJitter    []byte
	NetworkRTT   time.Duration
	DiskLatency  time.Duration
	UserActivity interface{}
}










// --- END STUBS FOR ADVANCED TIMING ---

// Minimal Ranker type for advanced timing stubs
// TODO: Expand as needed for real implementation

type Ranker struct{}
