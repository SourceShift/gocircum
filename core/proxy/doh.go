package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

// DoHResolver implements socks5.Resolver using DNS-over-HTTPS.
type DoHResolver struct {
	client      *http.Client
	resolverURL string
}

// NewDoHResolver creates a secure resolver pointing to a trusted DoH provider.
func NewDoHResolver() *DoHResolver {
	// Bootstrap with a hardcoded IP to prevent initial DNS leaks.
	// This is Cloudflare's 1.1.1.1.
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 10 * time.Second,
	}

	transport := &http.Transport{
		// Use a custom DialContext to force connection to the hardcoded IP.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// The address will be "dns.cloudflare.com:443", but we ignore it
			// and connect to the IP directly.
			return dialer.DialContext(ctx, "tcp", "1.1.1.1:443")
		},
		// The TLS ServerName must be set to the correct domain for validation.
		TLSClientConfig: &tls.Config{ServerName: "dns.cloudflare.com"},
	}

	return &DoHResolver{
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		resolverURL: "https://dns.cloudflare.com/dns-query",
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

// resolveWithRequest is a helper function to perform the DoH request and parse the response.
func (r *DoHResolver) resolveWithRequest(req *http.Request) (context.Context, net.IP, error) {
	ctx := req.Context()
	resp, err := r.client.Do(req)
	if err != nil {
		return ctx, nil, fmt.Errorf("failed to perform DoH request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ctx, nil, fmt.Errorf("DoH request failed with status: %s", resp.Status)
	}

	var dohResponse DoHResponse
	if err := json.NewDecoder(resp.Body).Decode(&dohResponse); err != nil {
		return ctx, nil, fmt.Errorf("failed to decode DoH response: %w", err)
	}

	for _, answer := range dohResponse.Answer {
		// Type 1 is an A record (IPv4).
		if answer.Type == 1 {
			ip := net.ParseIP(answer.Data)
			if ip != nil {
				return ctx, ip, nil
			}
		}
	}

	return ctx, nil, fmt.Errorf("no A records found for %s", req.URL.Query().Get("name"))
}

// Resolve uses DoH to resolve a domain name.
func (r *DoHResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", r.resolverURL+"?name="+name, nil)
	if err != nil {
		return ctx, nil, fmt.Errorf("failed to create DoH request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-json")
	return r.resolveWithRequest(req)
}
