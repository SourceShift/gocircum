package testutils

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/proxy"
)

// TestTimeout is the default timeout for operations in tests.
const TestTimeout = 5 * time.Second

// TestInterval is the default interval for polling in tests.
const TestInterval = 100 * time.Millisecond

var (
	testCert     tls.Certificate
	testCertErr  error
	testCertOnce sync.Once
)

// MockTLSEchoServer is a simple TLS server that echoes back any data it receives.
type MockTLSEchoServer struct {
	listener net.Listener
	addr     string
	cert     tls.Certificate
}

// NewMockTLSEchoServer creates and starts a new MockTLSEchoServer.
func NewMockTLSEchoServer() *MockTLSEchoServer {
	cert, err := getTestCert()
	if err != nil {
		panic(err)
	}

	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		panic(err)
	}

	s := &MockTLSEchoServer{
		listener: listener,
		addr:     listener.Addr().String(),
		cert:     cert,
	}
	go s.run()
	return s
}

func (s *MockTLSEchoServer) run() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return // Listener was closed
		}
		go func(c net.Conn) {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}(conn)
	}
}

// Addr returns the address of the server.
func (s *MockTLSEchoServer) Addr() string {
	return s.addr
}

// Close stops the server.
func (s *MockTLSEchoServer) Close() {
	s.listener.Close()
}

// getTestCert returns a cached test certificate, generating it only once.
func getTestCert() (tls.Certificate, error) {
	testCertOnce.Do(func() {
		testCert, testCertErr = generateTestCert()
	})
	return testCert, testCertErr
}

// generateTestCert creates a self-signed certificate for testing.
func generateTestCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPem, keyPem)
}

// CheckSOCKS5Proxy attempts to connect to a target address through a SOCKS5 proxy.
func CheckSOCKS5Proxy(proxyAddr, targetAddr string) error {
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	conn, err := dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Simple check: send data and expect it to be echoed back.
	payload := "hello"
	_, err = conn.Write([]byte(payload))
	if err != nil {
		return err
	}

	response := make([]byte, len(payload))
	_, err = io.ReadFull(conn, response)
	if err != nil {
		return fmt.Errorf("failed to read echo response: %w", err)
	}

	if string(response) != payload {
		return fmt.Errorf("unexpected response: got %q, want %q", string(response), payload)
	}

	return nil
}

// AssertConnectedToProxy is a helper for integration tests.
func AssertConnectedToProxy(t *testing.T, proxyAddr, targetAddr string) {
	err := CheckSOCKS5Proxy(proxyAddr, targetAddr)
	require.NoError(t, err, "Failed to connect to target through SOCKS5 proxy")
}

// AssertEventuallyConnectedToProxy polls until a connection to the target through the SOCKS5 proxy can be established.
func AssertEventuallyConnectedToProxy(t *testing.T, proxyAddr, targetAddr string) {
	t.Helper()
	require.Eventually(t, func() bool {
		return CheckSOCKS5Proxy(proxyAddr, targetAddr) == nil
	}, TestTimeout, TestInterval, "Timed out waiting for proxy connection")
}

// NewSOCKS5Client creates an http.Client that routes traffic through a SOCKS5 proxy.
func NewSOCKS5Client(proxyAddr string) (*http.Client, error) {
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}

	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			},
		},
	}, nil
}
