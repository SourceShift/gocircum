package core

import (
	"context"
	"gocircum/core/config"
	"gocircum/core/proxy"
	"gocircum/pkg/logging"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestEngine_Status(t *testing.T) {
	logger := logging.GetLogger()
	engine := &Engine{
		mu:     sync.Mutex{},
		logger: logger,
	}

	// 1. Test "Stopped" state
	assert.Equal(t, "Proxy stopped", engine.Status(), "Status should be 'Proxy stopped' when activeProxy is nil")

	// 2. Test "Running" state
	// We use a dummy proxy for this test since we don't need a real listener.
	engine.activeProxy = &proxy.Proxy{}
	assert.Contains(t, engine.Status(), "Proxy running on", "Status should be 'Proxy running' when activeProxy is not nil")

	// 3. Test that Status is idempotent
	assert.Contains(t, engine.Status(), "Proxy running on", "Calling Status again should yield the same result")

	// 4. Reset to stopped and check again
	engine.activeProxy = nil
	assert.Equal(t, "Proxy stopped", engine.Status(), "Status should be 'Proxy stopped' after proxy is set to nil")
}

func TestEngine_ProxyLifecycle(t *testing.T) {
	logger := logging.GetLogger()
	fp := config.Fingerprint{
		ID:          "test-tcp",
		Description: "Test TCP",
		Transport:   config.Transport{Protocol: "tcp"},
		TLS:         config.TLS{Library: "go-stdlib"},
	}
	engine, err := NewEngine([]config.Fingerprint{fp}, logger)
	assert.NoError(t, err, "NewEngine should not return an error")

	// 1. Start the proxy and check status
	addr := "127.0.0.1:0" // Use a random free port
	err = engine.StartProxyWithStrategy(context.Background(), addr, &fp)
	assert.NoError(t, err, "StartProxyWithStrategy should not return an immediate error")

	// Give the proxy a moment to start
	time.Sleep(100 * time.Millisecond)
	assert.Contains(t, engine.Status(), "Proxy running on", "Status should be 'Proxy running' after starting")

	// 2. Stop the proxy and check status
	err = engine.Stop()
	assert.NoError(t, err, "Stop should not return an error")
	assert.Equal(t, "Proxy stopped", engine.Status(), "Status should be 'Proxy stopped' after stopping")
}

func TestEngine_ProxyFailure(t *testing.T) {
	logger := logging.GetLogger()
	fp := config.Fingerprint{
		ID:          "test-tcp-failure",
		Description: "Test TCP Failure",
		Transport:   config.Transport{Protocol: "tcp"},
		TLS:         config.TLS{Library: "go-stdlib"},
	}
	engine, err := NewEngine([]config.Fingerprint{fp}, logger)
	assert.NoError(t, err, "NewEngine should not return an error")

	// Start the proxy
	addr := "127.0.0.1:0"
	err = engine.StartProxyWithStrategy(context.Background(), addr, &fp)
	assert.NoError(t, err, "StartProxyWithStrategy should not return an immediate error")
	time.Sleep(100 * time.Millisecond)
	assert.Contains(t, engine.Status(), "Proxy running on", "Proxy should be running initially")

	// Simulate a failure by closing the listener directly
	engine.mu.Lock()
	listener := engine.activeProxy.GetListener()
	engine.mu.Unlock()
	err = listener.Close()
	assert.NoError(t, err, "Closing the listener should not return an error")

	// Wait for the error to be processed
	select {
	case err := <-engine.proxyErrorChan:
		assert.Error(t, err, "An error should be received on the error channel")
		assert.Contains(t, err.Error(), "use of closed network connection", "Error should be about closed connection")
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for proxy error")
	}

	// Check final status
	assert.Equal(t, "Proxy stopped", engine.Status(), "Status should be 'Proxy stopped' after failure")
	assert.Nil(t, engine.activeProxy, "activeProxy should be nil after failure")
}
