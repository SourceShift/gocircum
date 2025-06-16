package transport

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/assert"
)

func TestNewQUICTransport(t *testing.T) {
	_, err := NewQUICTransport(&QUICConfig{
		TLSConfig: &utls.Config{},
	})
	if err != nil {
		t.Fatalf("Failed to create QUIC transport: %v", err)
	}
}

func TestQUICTransportListenContextCancellation(t *testing.T) {
	serverTLSConfig, err := generateQUICTestConfig("localhost")
	if err != nil {
		t.Fatalf("failed to generate server tls config: %v", err)
	}

	transport, err := NewQUICTransport(&QUICConfig{
		TLSConfig: serverTLSConfig,
	})
	if err != nil {
		t.Fatalf("Failed to create QUIC transport: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	listener, err := transport.Listen(ctx, "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	var wg sync.WaitGroup
	wg.Add(1)

	var acceptErr error
	go func() {
		defer wg.Done()
		// This will block until the context is canceled
		_, acceptErr = listener.Accept()
	}()

	// Give the goroutine a moment to block on Accept()
	time.Sleep(100 * time.Millisecond)

	// Cancel the context, which should unblock Accept()
	cancel()

	wg.Wait()

	assert.Error(t, acceptErr, "Accept should return an error after context cancellation")
	assert.ErrorIs(t, acceptErr, context.Canceled, "Error should be context.Canceled")
}

func TestQUICTransportListen_AlreadyCancelledContext(t *testing.T) {
	serverTLSConfig, err := generateQUICTestConfig("localhost")
	if err != nil {
		t.Fatalf("failed to generate server tls config: %v", err)
	}

	transport, err := NewQUICTransport(&QUICConfig{
		TLSConfig: serverTLSConfig,
	})
	if err != nil {
		t.Fatalf("Failed to create QUIC transport: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel context immediately

	_, err = transport.Listen(ctx, "udp", "127.0.0.1:0")
	assert.Error(t, err, "Listen should fail if context is already cancelled")
	// Note: uquic might not wrap the context error directly, so we check for its string representation.
	// This makes the test less brittle.
	assert.Contains(t, err.Error(), "context canceled", "Error should be related to context cancellation")
}

// generateQUICTestConfig creates a self-signed certificate and private key for testing.
func generateQUICTestConfig(host string) (*utls.Config, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("rsa.GenerateKey() err = %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("x509.CreateCertificate() err = %v", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	// utls.Config expects utls.Certificate, so we create one from the tls.Certificate.
	utlsCert := utls.Certificate{
		Certificate: tlsCert.Certificate,
		PrivateKey:  tlsCert.PrivateKey,
	}

	return &utls.Config{
		Certificates: []utls.Certificate{utlsCert},
	}, nil
}
