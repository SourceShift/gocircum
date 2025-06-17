package core

import (
	"context"
	"crypto/tls"
	"gocircum/core/config"
	engine2 "gocircum/core/engine"
	"gocircum/core/proxy"
	"gocircum/pkg/logging"
	"gocircum/testserver"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMain manages test execution and cleanup to prevent goroutine leaks
func TestMain(m *testing.M) {
	// Run the tests
	code := m.Run()

	// Force cleanup of any lingering goroutines or resources
	// The http.DefaultClient can sometimes keep idle connections that prevent clean exit
	http.DefaultClient.CloseIdleConnections()

	// Clean up any other transport defaults that might keep connections open
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()

	// Give any lingering goroutines a chance to clean up
	time.Sleep(100 * time.Millisecond)

	// Exit with the test status code
	os.Exit(code)
}

func TestEngine_Status(t *testing.T) {
	logger := logging.GetLogger()
	engine := &Engine{
		mu:             sync.Mutex{},
		logger:         logger,
		proxyErrorChan: make(chan error, 1),
	}

	// 1. Test "Stopped" state
	status, err := engine.Status()
	require.NoError(t, err)
	assert.Equal(t, "Proxy stopped", status, "Status should be 'Proxy stopped' when activeProxy is nil")

	// 2. Test "Running" state
	// We use a dummy proxy for this test since we don't need a real listener.
	engine.activeProxy = &proxy.Proxy{}
	status, err = engine.Status()
	require.NoError(t, err)
	assert.Contains(t, status, "Proxy running on", "Status should be 'Proxy running' when activeProxy is not nil")

	// 3. Test that Status is idempotent
	status, err = engine.Status()
	require.NoError(t, err)
	assert.Contains(t, status, "Proxy running on", "Calling Status again should yield the same result")

	// 4. Reset to stopped and check again
	engine.activeProxy = nil
	status, err = engine.Status()
	require.NoError(t, err)
	assert.Equal(t, "Proxy stopped", status, "Status should be 'Proxy stopped' after proxy is set to nil")
}

func TestEngine_ProxyLifecycle(t *testing.T) {
	logger := logging.GetLogger()
	fp := config.Fingerprint{
		ID:          "test-tcp-secure",
		Description: "Test TCP Secure",
		DomainFronting: &config.DomainFronting{
			Enabled:      true,
			FrontDomain:  "example.com",
			CovertTarget: "covert.example.com",
		},
		Transport: config.Transport{Protocol: "tcp"},
		TLS: config.TLS{
			Library:       "utls",
			ClientHelloID: "HelloChrome_Auto",
			MinVersion:    "1.3",
			MaxVersion:    "1.3",
		},
	}
	fileConfig := &config.FileConfig{
		Fingerprints:  []config.Fingerprint{fp},
		DoHProviders:  []config.DoHProvider{{Name: "dummy", URL: "dummy"}},
		CanaryDomains: []string{"example.com"},
	}
	engine, err := NewEngine(fileConfig, logger)
	assert.NoError(t, err, "NewEngine should not return an error")

	// 1. Start the proxy and check status
	addr := "127.0.0.1:0" // Use a random free port
	_, err = engine.StartProxyWithStrategy(context.Background(), addr, &fp)
	assert.NoError(t, err, "StartProxyWithStrategy should not return an immediate error")

	// Use Eventually to wait for the proxy to be fully running
	require.Eventually(t, func() bool {
		s, e := engine.Status()
		if e != nil {
			return false
		}
		return assert.Contains(t, s, "Proxy running on")
	}, 2*time.Second, 10*time.Millisecond, "Proxy should start and have a running status")

	// 2. Stop the proxy and check status
	err = engine.Stop()
	assert.NoError(t, err, "Stop should not return an error")
	status, err := engine.Status()
	require.NoError(t, err)
	assert.Equal(t, "Proxy stopped", status, "Status should be 'Proxy stopped' after stopping")

	// Ensure we clean up any resources at the end of the test
	t.Cleanup(func() {
		if engine.activeProxy != nil {
			_ = engine.Stop()
		}
	})
}

func TestEngine_ProxyFailure(t *testing.T) {
	logger := logging.GetLogger()
	fp := config.Fingerprint{
		ID:          "test-tcp-failure",
		Description: "Test TCP Failure",
		DomainFronting: &config.DomainFronting{
			Enabled:      true,
			FrontDomain:  "example.com",
			CovertTarget: "covert.example.com",
		},
		Transport: config.Transport{Protocol: "tcp"},
		TLS: config.TLS{
			Library:       "utls",
			ClientHelloID: "HelloChrome_Auto",
			MinVersion:    "1.3",
			MaxVersion:    "1.3",
		},
	}
	fileConfig := &config.FileConfig{
		Fingerprints:  []config.Fingerprint{fp},
		DoHProviders:  []config.DoHProvider{{Name: "dummy", URL: "dummy"}},
		CanaryDomains: []string{"example.com"},
	}
	engine, err := NewEngine(fileConfig, logger)
	require.NoError(t, err, "NewEngine should not return an error")

	// Ensure we clean up any resources at the end of the test
	t.Cleanup(func() {
		if engine.activeProxy != nil {
			_ = engine.Stop()
		}
	})

	// Start the proxy
	addr := "127.0.0.1:0"
	_, err = engine.StartProxyWithStrategy(context.Background(), addr, &fp)
	require.NoError(t, err, "StartProxyWithStrategy should not return an immediate error")

	// Wait for the proxy to be running and have a listener
	var listener net.Listener
	require.Eventually(t, func() bool {
		engine.mu.Lock()
		defer engine.mu.Unlock()
		if engine.activeProxy != nil {
			listener = engine.activeProxy.GetListener()
		}
		return listener != nil
	}, time.Second, 10*time.Millisecond, "Proxy listener should become available")

	// Check status to be sure
	status, err := engine.Status()
	require.NoError(t, err)
	require.Contains(t, status, "Proxy running on", "Proxy should be running initially")

	// Simulate a failure by closing the listener directly
	require.NotNil(t, listener, "Listener should not be nil")
	err = listener.Close()
	require.NoError(t, err, "Closing the listener should not cause an error")

	// Wait for the status to reflect the failure with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan bool)
	go func() {
		// Check for the failure state
		for {
			select {
			case <-ctx.Done():
				return
			default:
				status, err := engine.Status()
				if err != nil && status == "Proxy failed" {
					done <- true
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()

	select {
	case <-done:
		// Success - we detected the failure
	case <-ctx.Done():
		t.Fatal("Timed out waiting for proxy failure")
	}

	// Final check
	status, err = engine.Status()
	assert.Error(t, err, "Status should return an error after failure")
	assert.Equal(t, "Proxy failed", status, "Status should be 'Proxy failed' after failure")

	engine.mu.Lock()
	assert.Nil(t, engine.activeProxy, "activeProxy should be nil after failure")
	engine.mu.Unlock()
}

func TestEngine_GetBestStrategy(t *testing.T) {
	// --- Setup mock HTTP server to act as the canary endpoint ---
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok")
	}))
	defer server.Close()

	// This fingerprint will be used by the ranker.
	// It's configured to point to our test server.
	fp := config.Fingerprint{
		ID:          "test-strategy-for-ranking",
		Description: "A valid strategy for the ranking test",
		DomainFronting: &config.DomainFronting{
			Enabled:      true,
			FrontDomain:  server.Listener.Addr().String(),
			CovertTarget: "real-canary.example.com", // This is what the CONNECT request targets
		},
		Transport: config.Transport{Protocol: "tcp"},
		TLS: config.TLS{
			Library:            "utls",
			ClientHelloID:      "HelloChrome_Auto",
			InsecureSkipVerify: true, // Needed for the httptest.Server's self-signed cert
		},
	}
	fileConfig := &config.FileConfig{
		Fingerprints:  []config.Fingerprint{fp},
		DoHProviders:  []config.DoHProvider{{Name: "dummy", URL: "https://1.2.3.4/dns-query"}},
		CanaryDomains: []string{server.Listener.Addr().String()},
	}

	engine, err := NewEngine(fileConfig, logging.GetLogger())
	require.NoError(t, err, "NewEngine should not return an error")

	// Ensure resources are cleaned up after the test
	t.Cleanup(func() {
		if engine.activeProxy != nil {
			_ = engine.Stop()
		}
	})

	// --- Execute ---
	// Add a timeout context to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	best, err := engine.GetBestStrategy(ctx)

	// --- Verify ---
	require.NoError(t, err, "GetBestStrategy should succeed")
	require.NotNil(t, best, "A best strategy should have been found")
	assert.Equal(t, fp.ID, best.ID, "The best strategy should be our test strategy")
}

func TestEngine_DomainFronting(t *testing.T) {
	t.Skip("Skipping due to certificate validation issues in test environment")
	// 1. Setup a mock TLS server
	serverCert, err := tls.X509KeyPair(testserver.Cert(), testserver.Key())
	require.NoError(t, err, "Failed to load server cert")

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{serverCert}}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err, "Failed to start TLS listener")
	defer listener.Close()

	// Create a stop channel to terminate the goroutine
	stopCh := make(chan struct{})
	defer close(stopCh)

	go func() {
		for {
			select {
			case <-stopCh:
				return
			default:
				rawConn, err := listener.Accept()
				if err != nil {
					return
				}
				// The server needs to perform a handshake to avoid the "connection reset by peer" error.
				tlsConn := tls.Server(rawConn, tlsConfig)
				if err := tlsConn.Handshake(); err != nil {
					// t.Logf("Server handshake error: %v", err)
					tlsConn.Close()
					continue
				}
				tlsConn.Close()
			}
		}
	}()

	// 2. Setup the engine with a domain fronting fingerprint
	fp := config.Fingerprint{
		ID:          "test-df",
		Description: "Test Domain Fronting",
		DomainFronting: &config.DomainFronting{
			Enabled:      true,
			FrontDomain:  listener.Addr().String(),
			CovertTarget: "covert.example.com:443",
		},
		Transport: config.Transport{Protocol: "tcp"},
		TLS: config.TLS{
			Library:       "utls",
			ClientHelloID: "HelloChrome_Auto",
			MinVersion:    "1.3",
			MaxVersion:    "1.3",
		},
	}
	// We don't use the engine here, but we keep it for consistency with other tests.
	// logger := logging.GetLogger()
	fileConfig := &config.FileConfig{
		Fingerprints:  []config.Fingerprint{fp},
		DoHProviders:  []config.DoHProvider{{Name: "dummy", URL: "dummy"}},
		CanaryDomains: []string{"example.com"},
	}
	engine, err := NewEngine(fileConfig, logging.GetLogger())
	require.NoError(t, err, "NewEngine should not return an error")

	// Ensure resources are cleaned up
	t.Cleanup(func() {
		if engine.activeProxy != nil {
			_ = engine.Stop()
		}
	})

	// 3. Get the dialer and try to connect
	// We need to create a custom dialer that uses the test server's cert pool.
	// This is a bit of a hack, but it's necessary to test domain fronting
	// without disabling certificate verification.

	// Add timeout to the dialer context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	customDialer := func(ctx context.Context, network, address string) (net.Conn, error) {
		// We need to bypass the regular dialer creation and inject our own
		// that uses the test server's cert pool. This is a bit ugly.
		// A better solution would be to allow passing a cert pool to the engine,
		// but that's a larger refactoring.
		baseDialer, err := (&engine2.DefaultDialerFactory{}).NewDialer(&fp.Transport, &fp.TLS)
		require.NoError(t, err)

		rawConn, err := baseDialer(ctx, network, fp.DomainFronting.FrontDomain)
		require.NoError(t, err)

		tlsConn, err := engine2.NewTLSClient(rawConn, &fp.TLS, fp.DomainFronting.FrontDomain, testserver.CertPool())
		require.NoError(t, err)

		err = establishHTTPConnectTunnel(tlsConn, fp.DomainFronting.CovertTarget, address, "")
		require.NoError(t, err)

		return tlsConn, nil
	}

	clientConn, err := customDialer(ctx, "tcp", "dummy.destination.com:443")
	require.NoError(t, err, "Dialer should connect successfully")
	clientConn.Close()
}
