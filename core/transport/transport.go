//go:generate mockgen -package=mocks -destination=../../mocks/mock_transport.go github.com/gocircum/gocircum/core/transport Transport

package transport

import (
	"context"
	"errors"
	"net"
	"time"
)

// Transport interface extended for censorship resistance
type Transport interface {
	// DialContext connects to the given address.
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	// Listen creates a listener on the specified network address.
	Listen(ctx context.Context, network, address string) (net.Listener, error)
	// Close closes the transport, releasing any resources.
	Close() error
	
	// Hardened: Additional methods for censorship resistance
	// GetFingerprint returns the network-observable characteristics of this transport
	GetFingerprint() TransportFingerprint
	// GenerateDecoyTraffic creates realistic background traffic to mask real connections
	GenerateDecoyTraffic(ctx context.Context, targetAddr string) error
	// SupportsObfuscation indicates if the transport can masquerade as other protocols
	SupportsObfuscation() bool
	// SetObfuscationTarget configures the transport to mimic a specific protocol
	SetObfuscationTarget(target ObfuscationTarget) error
}

// TransportFingerprint describes the observable network characteristics
type TransportFingerprint struct {
	Protocol         string
	PacketSizes      []int
	TimingPattern    []time.Duration
	TLSSignature     string
	ObfuscationLevel ObfuscationLevel
}

type ObfuscationLevel int
const (
	ObfuscationNone ObfuscationLevel = iota
	ObfuscationBasic
	ObfuscationAdvanced
	ObfuscationMaximal
)

type ObfuscationTarget int
const (
	ObfuscateAsHTTP ObfuscationTarget = iota
	ObfuscateAsSSH
	ObfuscateAsBitTorrent
	ObfuscateAsVideoStream
	ObfuscateAsVoIP
	ObfuscateAsWebRTC
	ObfuscateAsMinecraft
)

// Middleware is a function that wraps a Transport to add functionality.
type Middleware func(transport Transport) Transport

// Config is a placeholder for common configuration options.
type Config struct {
	DialTimeout        time.Duration
	ReadTimeout        time.Duration
	WriteTimeout       time.Duration
	ObfuscationEnabled bool
	ObfuscationTarget  ObfuscationTarget
	DecoyTrafficRate   time.Duration // How often to generate decoy traffic
}

// Factory is a function that creates a new Transport with the given config.
type Factory func(cfg *Config) (Transport, error)

// Custom error types for the transport layer.
var (
	ErrTimeout   = &net.DNSError{Err: "i/o timeout", IsTimeout: true}
	ErrHandshake = errors.New("handshake failed")
)
