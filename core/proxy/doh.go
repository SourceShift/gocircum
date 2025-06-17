package proxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"gocircum/core/config"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

var (
	// A list of trusted DoH providers.
	dohProviders = []config.DoHProvider{
		{
			Name:       "Cloudflare",
			URL:        "https://dns.cloudflare.com/dns-query",
			ServerName: "dns.cloudflare.com",
			Bootstrap:  []string{"1.1.1.1:443", "1.0.0.1:443"},
		},
		{
			Name:       "Google",
			URL:        "https://dns.google/resolve",
			ServerName: "dns.google",
			Bootstrap:  []string{"8.8.8.8:443", "8.8.4.4:443"},
		},
		{
			Name:       "Quad9",
			URL:        "https://dns.quad9.net/dns-query",
			ServerName: "dns.quad9.net",
			Bootstrap:  []string{"9.9.9.9:443", "149.112.112.112:443"},
		},
	}
	mu sync.Mutex
)

// DoHResolver implements socks5.Resolver using DNS-over-HTTPS.
type DoHResolver struct {
	providers []config.DoHProvider
}

// NewDoHResolver creates a secure resolver that uses a set of trusted DoH providers.
func NewDoHResolver(providers []config.DoHProvider) *DoHResolver {
	if len(providers) == 0 {
		// Fallback to the default list if none are provided.
		return &DoHResolver{providers: dohProviders}
	}
	return &DoHResolver{
		providers: providers,
	}
}

// getShuffledProviders returns a shuffled copy of the DoH providers.
func (r *DoHResolver) getShuffledProviders() []config.DoHProvider {
	mu.Lock()
	defer mu.Unlock()
	shuffled := make([]config.DoHProvider, len(r.providers))
	copy(shuffled, r.providers)

	// Fisher-Yates shuffle using crypto/rand for secure, unpredictable shuffling.
	for i := len(shuffled) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			// A failure in rand.Reader is a serious system issue.
			// Returning the list unshuffled is a safe fallback.
			return shuffled
		}
		shuffled[i], shuffled[j.Int64()] = shuffled[j.Int64()], shuffled[i]
	}
	return shuffled
}

var createClientForProvider = func(provider config.DoHProvider) *http.Client {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 10 * time.Second,
	}

	tlsConfig := &tls.Config{ServerName: provider.ServerName}
	if provider.RootCA != "" {
		caCertPool := x509.NewCertPool()
		// We can ignore the boolean return value. If the PEM data is invalid,
		// AppendCertsFromPEM will just not add any certs to the pool, and we'll
		// proceed with the system's default trust store.
		caCertPool.AppendCertsFromPEM([]byte(provider.RootCA))
		tlsConfig.RootCAs = caCertPool
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			shuffledBootstrap := make([]string, len(provider.Bootstrap))
			copy(shuffledBootstrap, provider.Bootstrap)

			// Fisher-Yates shuffle for bootstrap IPs.
			for i := len(shuffledBootstrap) - 1; i > 0; i-- {
				j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
				if err != nil {
					return nil, fmt.Errorf("failed to shuffle bootstrap IPs for %s: %w", provider.Name, err)
				}
				shuffledBootstrap[i], shuffledBootstrap[j.Int64()] = shuffledBootstrap[j.Int64()], shuffledBootstrap[i]
			}

			var lastErr error
			for _, bootstrapAddr := range shuffledBootstrap {
				conn, err := dialer.DialContext(ctx, "tcp", bootstrapAddr)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, fmt.Errorf("failed to connect to any bootstrap server for %s: %w", provider.Name, lastErr)
		},
		TLSClientConfig: tlsConfig,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
}

// DoHResponse represents the JSON structure of a DoH response.
type DoHResponse struct {
	Status int         `json:"Status"`
	Answer []DoHAnswer `json:"Answer"`
}

// DoHAnswer represents a single answer in a DoH response.
type DoHAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	Data string `json:"data"`
}

// Resolve uses DoH to resolve a domain name, trying multiple providers on failure.
func (r *DoHResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	shuffledProviders := r.getShuffledProviders()
	var lastErr error

	for _, provider := range shuffledProviders {
		client := createClientForProvider(provider)

		reqURL, err := url.Parse(provider.URL)
		if err != nil {
			lastErr = fmt.Errorf("invalid URL for provider %s: %w", provider.Name, err)
			continue
		}
		q := reqURL.Query()
		q.Set("name", name)
		reqURL.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, "GET", reqURL.String(), nil)
		if err != nil {
			lastErr = fmt.Errorf("failed to create DoH request for %s: %w", provider.Name, err)
			continue
		}
		req.Header.Set("Accept", "application/dns-json")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("failed to perform DoH request to %s: %w", provider.Name, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("DoH request to %s failed with status: %s", provider.Name, resp.Status)
			continue
		}

		var dohResponse DoHResponse
		if err := json.NewDecoder(resp.Body).Decode(&dohResponse); err != nil {
			resp.Body.Close()
			lastErr = fmt.Errorf("failed to decode DoH response from %s: %w", provider.Name, err)
			continue
		}
		resp.Body.Close()

		for _, answer := range dohResponse.Answer {
			// Type 1 is an A record (IPv4).
			if answer.Type == 1 {
				ip := net.ParseIP(answer.Data)
				if ip != nil {
					return ctx, ip, nil
				}
			}
		}
		// If we are here, we got a valid response, but no A record.
		// We can consider this a "soft" failure and try the next provider.
		lastErr = fmt.Errorf("no A records found for %s from %s", name, provider.Name)
	}

	return ctx, nil, fmt.Errorf("failed to resolve domain %s using any DoH provider: %w", name, lastErr)
}
