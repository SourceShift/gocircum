package proxy

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"gocircum/core/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetShuffledProviders(t *testing.T) {
	resolver := NewDoHResolver(nil)
	shuffled1 := resolver.getShuffledProviders()
	shuffled2 := resolver.getShuffledProviders()

	if reflect.DeepEqual(shuffled1, shuffled2) {
		t.Log("Provider lists are the same, which is possible but unlikely. Running test again.")
		shuffled2 = resolver.getShuffledProviders()
		if reflect.DeepEqual(shuffled1, shuffled2) {
			t.Errorf("Expected provider lists to be shuffled and different, but they were the same twice.")
		}
	}

	if len(shuffled1) != len(dohProviders) {
		t.Errorf("Expected shuffled list to have length %d, but got %d", len(dohProviders), len(shuffled1))
	}
}

func TestDoHResolver_Resolve_Failover(t *testing.T) {
	var workingServerRequests int32
	workingServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&workingServerRequests, 1)
		w.Header().Set("Content-Type", "application/dns-json")
		_, err := io.WriteString(w, `{"Status": 0, "Answer": [{"name": "example.com", "type": 1, "data": "93.184.216.34"}]}`)
		require.NoError(t, err)
	}))
	defer workingServer.Close()

	failingServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failingServer.Close()

	resolver := NewDoHResolver(nil)

	// Override providers for test
	resolver.providers = []config.DoHProvider{
		{
			Name:       "Failing",
			URL:        failingServer.URL,
			ServerName: "example.com",
			Bootstrap:  []string{failingServer.Listener.Addr().String()},
		},
		{
			Name:       "Working",
			URL:        workingServer.URL,
			ServerName: "example.com",
			Bootstrap:  []string{workingServer.Listener.Addr().String()},
		},
	}

	// Because we use a test server, we need to add its cert to the trust pool for the HTTP client.
	// We can do this by modifying the createClientForProvider function for the test.
	originalCreateClient := createClientForProvider
	defer func() { createClientForProvider = originalCreateClient }()
	createClientForProvider = func(provider config.DoHProvider) (*http.Client, error) {
		client, err := originalCreateClient(provider)
		if err != nil {
			return nil, err
		}
		transport := client.Transport.(*http.Transport)
		certpool := x509.NewCertPool()
		certpool.AddCert(workingServer.Certificate())
		certpool.AddCert(failingServer.Certificate())
		transport.TLSClientConfig.RootCAs = certpool
		return client, nil
	}

	_, ip, err := resolver.Resolve(context.Background(), "example.com")
	require.NoError(t, err)
	assert.Equal(t, "93.184.216.34", ip.String())
	assert.Equal(t, int32(1), atomic.LoadInt32(&workingServerRequests), "Working server should have been called once")
}

func TestDoHResolver_Resolve_AllFail(t *testing.T) {
	failingServer1 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failingServer1.Close()

	failingServer2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGatewayTimeout)
	}))
	defer failingServer2.Close()

	resolver := NewDoHResolver(nil)
	resolver.providers = []config.DoHProvider{
		{
			Name:       "Failing1",
			URL:        failingServer1.URL,
			ServerName: "example.com",
			Bootstrap:  []string{failingServer1.Listener.Addr().String()},
		},
		{
			Name:       "Failing2",
			URL:        failingServer2.URL,
			ServerName: "example.com",
			Bootstrap:  []string{failingServer2.Listener.Addr().String()},
		},
	}

	originalCreateClient := createClientForProvider
	defer func() { createClientForProvider = originalCreateClient }()
	createClientForProvider = func(provider config.DoHProvider) (*http.Client, error) {
		client, err := originalCreateClient(provider)
		if err != nil {
			return nil, err
		}
		transport := client.Transport.(*http.Transport)
		certpool := x509.NewCertPool()
		certpool.AddCert(failingServer1.Certificate())
		certpool.AddCert(failingServer2.Certificate())
		transport.TLSClientConfig.RootCAs = certpool
		// Shorten timeout to make test run faster
		client.Timeout = 200 * time.Millisecond
		return client, nil
	}

	_, _, err := resolver.Resolve(context.Background(), "example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to resolve domain example.com using any DoH provider")
}

func TestDoHResolver_Resolve(t *testing.T) {
	t.Run("successful resolution", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/dns-query", r.URL.Path)
			assert.Equal(t, "example.com", r.URL.Query().Get("name"))
			assert.Equal(t, "application/dns-json", r.Header.Get("Accept"))
			w.Header().Set("Content-Type", "application/dns-json")
			_, err := io.WriteString(w, `{
				"Status": 0,
				"Answer": [
					{"name": "example.com", "type": 1, "data": "93.184.216.34"}
				]
			}`)
			require.NoError(t, err)
		}))
		defer server.Close()

		resolver := NewDoHResolver(nil)
		resolver.providers = []config.DoHProvider{
			{
				Name:       "TestServer",
				URL:        server.URL + "/dns-query",
				ServerName: "example.com",
				Bootstrap:  []string{server.Listener.Addr().String()},
			},
		}

		originalCreateClient := createClientForProvider
		defer func() { createClientForProvider = originalCreateClient }()
		createClientForProvider = func(provider config.DoHProvider) (*http.Client, error) {
			client, err := originalCreateClient(provider)
			if err != nil {
				return nil, err
			}
			transport := client.Transport.(*http.Transport)
			certpool := x509.NewCertPool()
			certpool.AddCert(server.Certificate())
			transport.TLSClientConfig.RootCAs = certpool
			return client, nil
		}

		_, ip, err := resolver.Resolve(context.Background(), "example.com")
		require.NoError(t, err)
		assert.Equal(t, "93.184.216.34", ip.String())
	})

	t.Run("no A records", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/dns-json")
			// Response for a CNAME record, but no A record
			_, err := io.WriteString(w, `{
				"Status": 0,
				"Answer": [
					{"name": "example.com", "type": 5, "data": "cname.example.net"}
				]
			}`)
			require.NoError(t, err)
		}))
		defer server.Close()

		resolver := NewDoHResolver(nil)
		resolver.providers = []config.DoHProvider{
			{
				Name:       "TestServer",
				URL:        server.URL,
				ServerName: "example.com",
				Bootstrap:  []string{server.Listener.Addr().String()},
			},
		}

		originalCreateClient := createClientForProvider
		defer func() { createClientForProvider = originalCreateClient }()
		createClientForProvider = func(provider config.DoHProvider) (*http.Client, error) {
			client, err := originalCreateClient(provider)
			if err != nil {
				return nil, err
			}
			transport := client.Transport.(*http.Transport)
			certpool := x509.NewCertPool()
			certpool.AddCert(server.Certificate())
			transport.TLSClientConfig.RootCAs = certpool
			return client, nil
		}

		_, _, err := resolver.Resolve(context.Background(), "example.com")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no A records found for example.com from TestServer")
	})
}

func TestCreateClientForProvider_BootstrapFailover(t *testing.T) {
	workingServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Just needs to accept a connection
	}))
	defer workingServer.Close()

	provider := config.DoHProvider{
		Name:       "Test",
		URL:        "https://example.com",
		ServerName: "example.com",
		Bootstrap: []string{
			"127.0.0.1:12345", // Bad address
			workingServer.Listener.Addr().String(),
		},
	}

	client, err := createClientForProvider(provider)
	require.NoError(t, err)
	transport := client.Transport.(*http.Transport)
	certpool := x509.NewCertPool()
	certpool.AddCert(workingServer.Certificate())
	transport.TLSClientConfig.RootCAs = certpool

	// This request should succeed because the dialer will failover to the working bootstrap server
	req, err := http.NewRequest("GET", workingServer.URL, nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
}
