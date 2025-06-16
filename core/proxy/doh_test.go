package proxy

import (
	"context"
	"testing"
)

func TestDoHResolver_Resolve(t *testing.T) {
	resolver := NewDoHResolver()
	ctx := context.Background()

	_, ip, err := resolver.Resolve(ctx, "www.cloudflare.com")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	if ip == nil {
		t.Fatal("Resolve() got nil IP")
	}

	t.Logf("Resolved www.cloudflare.com to %s", ip.String())
}
