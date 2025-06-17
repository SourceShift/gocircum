package proxy

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"gocircum/core/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func certToPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

func TestGetShuffledProviders(t *testing.T) {
	providers := []config.DoHProvider{
		{Name: "1"}, {Name: "2"}, {Name: "3"},
	}
	resolver, err := NewDoHResolver(providers)
	require.NoError(t, err)

	shuffled1 := resolver.getShuffledProviders()
	shuffled2 := resolver.getShuffledProviders()

	if reflect.DeepEqual(shuffled1, shuffled2) {
		t.Log("Provider lists are the same, which is possible but unlikely. Running test again.")
		shuffled2 = resolver.getShuffledProviders()
		if reflect.DeepEqual(shuffled1, shuffled2) {
			t.Errorf("Expected provider lists to be shuffled and different, but they were the same twice.")
		}
	}

	require.Equal(t, len(providers), len(shuffled1), "Expected shuffled list to have the same length as the original")
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

	dummyProviders := []config.DoHProvider{{Name: "dummy"}}
	resolver, err := NewDoHResolver(dummyProviders)
	require.NoError(t, err)

	// We need to provide the test server's certificate to the client.
	// The new uTLS client uses the RootCA field on the provider.
	// We create a PEM string containing both certs.
	allCertsPEM := certToPEM(failingServer.Certificate()) + certToPEM(workingServer.Certificate())

	workingHost, _, err := net.SplitHostPort(workingServer.Listener.Addr().String())
	require.NoError(t, err)

	failingHost, _, err := net.SplitHostPort(failingServer.Listener.Addr().String())
	require.NoError(t, err)

	// Override providers for test
	resolver.providers = []config.DoHProvider{
		{
			Name:       "Failing",
			URL:        failingServer.URL,
			ServerName: "example.com",
			Bootstrap:  []string{failingHost},
			RootCA:     allCertsPEM,
		},
		{
			Name:       "Working",
			URL:        workingServer.URL,
			ServerName: "example.com",
			Bootstrap:  []string{workingHost},
			RootCA:     allCertsPEM,
		},
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

	dummyProviders := []config.DoHProvider{{Name: "dummy"}}
	resolver, err := NewDoHResolver(dummyProviders)
	require.NoError(t, err)

	allCertsPEM := certToPEM(failingServer1.Certificate()) + certToPEM(failingServer2.Certificate())

	host1, _, err := net.SplitHostPort(failingServer1.Listener.Addr().String())
	require.NoError(t, err)
	host2, _, err := net.SplitHostPort(failingServer2.Listener.Addr().String())
	require.NoError(t, err)

	resolver.providers = []config.DoHProvider{
		{
			Name:       "Failing1",
			URL:        failingServer1.URL,
			ServerName: "example.com",
			Bootstrap:  []string{host1},
			RootCA:     allCertsPEM,
		},
		{
			Name:       "Failing2",
			URL:        failingServer2.URL,
			ServerName: "example.com",
			Bootstrap:  []string{host2},
			RootCA:     allCertsPEM,
		},
	}

	// We can't easily modify the client timeout with the new setup,
	// so we remove the monkey-patch that did that. The test will run a bit slower.
	_, _, err = resolver.Resolve(context.Background(), "example.com")
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

		dummyProviders := []config.DoHProvider{{Name: "dummy"}}
		resolver, err := NewDoHResolver(dummyProviders)
		require.NoError(t, err)

		host, _, err := net.SplitHostPort(server.Listener.Addr().String())
		require.NoError(t, err)

		resolver.providers = []config.DoHProvider{
			{
				Name:       "TestServer",
				URL:        server.URL + "/dns-query",
				ServerName: "example.com",
				Bootstrap:  []string{host},
				RootCA:     certToPEM(server.Certificate()),
			},
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

		dummyProviders := []config.DoHProvider{{Name: "dummy"}}
		resolver, err := NewDoHResolver(dummyProviders)
		require.NoError(t, err)

		host, _, err := net.SplitHostPort(server.Listener.Addr().String())
		require.NoError(t, err)

		resolver.providers = []config.DoHProvider{
			{
				Name:       "TestServer",
				URL:        server.URL,
				ServerName: "example.com",
				Bootstrap:  []string{host},
				RootCA:     certToPEM(server.Certificate()),
			},
		}

		_, _, err = resolver.Resolve(context.Background(), "example.com")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no A records found for example.com from TestServer")
	})
}

func TestCreateClientForProvider_BootstrapFailover(t *testing.T) {
	workingServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Just needs to accept a connection
	}))
	defer workingServer.Close()

	workingHost, _, err := net.SplitHostPort(workingServer.Listener.Addr().String())
	require.NoError(t, err)

	provider := config.DoHProvider{
		Name:       "Test",
		URL:        "https://example.com",
		ServerName: "example.com",
		Bootstrap: []string{
			"127.0.0.1", // Bad address, will fail to connect and cause failover
			workingHost,
		},
		RootCA: certToPEM(workingServer.Certificate()),
	}

	client, err := createClientForProvider(provider)
	require.NoError(t, err)

	// This request should succeed because the dialer will failover to the working bootstrap server
	req, err := http.NewRequest("GET", workingServer.URL, nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
}
