package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"crypto/x509"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

		resolver := NewDoHResolver()
		resolver.resolverURL = server.URL + "/dns-query"
		certpool := x509.NewCertPool()
		certpool.AddCert(server.Certificate())
		resolver.client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certpool,
			},
		}

		_, ip, err := resolver.Resolve(context.Background(), "example.com")
		require.NoError(t, err)
		assert.Equal(t, "93.184.216.34", ip.String())
	})

	t.Run("http error", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		resolver := NewDoHResolver()
		resolver.resolverURL = server.URL + "/dns-query"
		certpool := x509.NewCertPool()
		certpool.AddCert(server.Certificate())
		resolver.client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certpool,
			},
		}

		_, _, err := resolver.Resolve(context.Background(), "example.com")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "DoH request failed with status: 500 Internal Server Error")
	})

	t.Run("malformed json", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/dns-json")
			_, err := io.WriteString(w, `{"Status": 0, "Answer": [`)
			require.NoError(t, err)
		}))
		defer server.Close()

		resolver := NewDoHResolver()
		resolver.resolverURL = server.URL + "/dns-query"
		certpool := x509.NewCertPool()
		certpool.AddCert(server.Certificate())
		resolver.client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certpool,
			},
		}

		_, _, err := resolver.Resolve(context.Background(), "example.com")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode DoH response")
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

		resolver := NewDoHResolver()
		resolver.resolverURL = server.URL + "/dns-query"
		certpool := x509.NewCertPool()
		certpool.AddCert(server.Certificate())
		resolver.client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certpool,
			},
		}

		_, _, err := resolver.Resolve(context.Background(), "example.com")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no A records found for example.com")
	})

	t.Run("context cancellation", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		resolver := NewDoHResolver()
		resolver.resolverURL = server.URL + "/dns-query"
		certpool := x509.NewCertPool()
		certpool.AddCert(server.Certificate())
		resolver.client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certpool,
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		_, _, err := resolver.Resolve(ctx, "example.com")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "context deadline exceeded")
	})
}
