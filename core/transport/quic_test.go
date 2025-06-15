package transport

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestNewQUICTransport(t *testing.T) {
	_, err := NewQUICTransport(&QUICConfig{
		TLSConfig: &utls.Config{},
	})
	if err != nil {
		t.Fatalf("Failed to create QUIC transport: %v", err)
	}
}
