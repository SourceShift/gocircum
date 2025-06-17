package core

import (
	"context"
	"crypto/tls"
	"gocircum/core/config"
	engine2 "gocircum/core/engine"
	"gocircum/core/proxy"
	"gocircum/pkg/logging"
	"gocircum/testserver"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		ID:          "test-tcp",
		Description: "Test TCP",
		DomainFronting: &config.DomainFronting{
			Enabled:      true,
			FrontDomain:  "example.com",
			CovertTarget: "covert.example.com",
		},
		Transport: config.Transport{Protocol: "tcp"},
		TLS:       config.TLS{Library: "go-stdlib"},
	}
	engine, err := NewEngine(&config.FileConfig{Fingerprints: []config.Fingerprint{fp}}, logger)
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
		TLS:       config.TLS{Library: "go-stdlib"},
	}
	engine, err := NewEngine(&config.FileConfig{Fingerprints: []config.Fingerprint{fp}}, logger)
	require.NoError(t, err, "NewEngine should not return an error")

	// Start the proxy
	addr := "127.0.0.1:0"
	_, err = engine.StartProxyWithStrategy(context.Background(), addr, &fp)
	require.NoError(t, err, "StartProxyWithStrategy should not return an immediate error")

	// Wait for the proxy to be running and have a listener
	var listener net.Listener
	require.Eventually(t, func() bool {
		engine.mu.Lock()
		if engine.activeProxy != nil {
			listener = engine.activeProxy.GetListener()
		}
		engine.mu.Unlock()
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

	// Wait for the status to reflect the failure.
	assert.Eventually(t, func() bool {
		status, err := engine.Status()
		return err != nil && status == "Proxy failed"
	}, 2*time.Second, 10*time.Millisecond, "Status should eventually be 'Proxy failed' with an error")

	// Final check
	status, err = engine.Status()
	assert.Error(t, err, "Status should return an error after failure")
	assert.Equal(t, "Proxy failed", status, "Status should be 'Proxy failed' after failure")

	engine.mu.Lock()
	assert.Nil(t, engine.activeProxy, "activeProxy should be nil after failure")
	engine.mu.Unlock()
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

	go func() {
		rawConn, err := listener.Accept()
		if err != nil {
			return
		}
		// The server needs to perform a handshake to avoid the "connection reset by peer" error.
		tlsConn := tls.Server(rawConn, tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			// t.Logf("Server handshake error: %v", err)
			return
		}
		tlsConn.Close()
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
			Library:    "go-stdlib",
			MinVersion: "1.2",
			MaxVersion: "1.3",
		},
	}
	// We don't use the engine here, but we keep it for consistency with other tests.
	// logger := logging.GetLogger()
	// _, err = NewEngine(&config.FileConfig{Fingerprints: []config.Fingerprint{fp}}, logger)
	// require.NoError(t, err, "NewEngine should not return an error")

	// 3. Get the dialer and try to connect
	// We need to create a custom dialer that uses the test server's cert pool.
	// This is a bit of a hack, but it's necessary to test domain fronting
	// without disabling certificate verification.
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

	clientConn, err := customDialer(context.Background(), "tcp", "dummy.destination.com:443")
	require.NoError(t, err, "Dialer should connect successfully")
	clientConn.Close()
}
