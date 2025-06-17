package ranker

import (
	"context"
	"fmt"
	"gocircum/core/config"
	"gocircum/core/engine"
	"gocircum/testutils"
	"net"
	"testing"
	"time"

	"go.uber.org/mock/gomock"
)

// mockResolver implements the DNSResolver interface for testing.
type mockResolver struct{}

func (m *mockResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	if name == "www.example.com" {
		return ctx, net.ParseIP("1.2.3.4"), nil
	}
	return ctx, nil, fmt.Errorf("domain not found in mock resolver: %s", name)
}

// mockDialer simulates network dialing for tests.
// It now checks if the address is the expected IP.
func mockDialer(t *testing.T, ctrl *gomock.Controller, succeed bool, delay time.Duration, expectedAddr string) engine.Dialer {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != expectedAddr {
			t.Errorf("dialer called with wrong address: got %s, want %s", address, expectedAddr)
			return nil, fmt.Errorf("unexpected address for dialer")
		}

		if succeed {
			time.Sleep(delay)
			conn := testutils.NewMockConn(ctrl)
			conn.EXPECT().Close().Return(nil).AnyTimes()
			return conn, nil
		}
		return nil, &net.OpError{Op: "dial", Net: network, Addr: nil, Err: &net.DNSError{Err: "no such host"}}
	}
}

type mockDialerFactory struct {
	t    *testing.T
	ctrl *gomock.Controller
}

func (f *mockDialerFactory) NewDialer(transportCfg *config.Transport, tlsCfg *config.TLS) (engine.Dialer, error) {
	// The mock dialer now needs the expected IP address.
	expectedAddr := "1.2.3.4:443" // Based on mockResolver and default port.

	switch tlsCfg.ClientHelloID {
	case "fp1":
		return mockDialer(f.t, f.ctrl, true, 50*time.Millisecond, expectedAddr), nil
	case "fp2":
		return mockDialer(f.t, f.ctrl, true, 150*time.Millisecond, expectedAddr), nil
	default:
		return mockDialer(f.t, f.ctrl, false, 0, expectedAddr), nil
	}
}

func TestRanker_TestAndRank(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	logger := testutils.NewTestLogger()
	ranker := NewRanker(logger, nil)
	ranker.DialerFactory = &mockDialerFactory{t: t, ctrl: ctrl} // Inject the mock factory
	ranker.DoHResolver = &mockResolver{}                        // Inject the mock resolver

	fingerprints := []*config.Fingerprint{
		{ID: "fp1", TLS: config.TLS{ClientHelloID: "fp1"}}, // Should succeed fast
		{ID: "fp2", TLS: config.TLS{ClientHelloID: "fp2"}}, // Should succeed slow
		{ID: "fp3", TLS: config.TLS{ClientHelloID: "fp3"}}, // Should fail
	}

	canaryDomains := []string{"www.example.com"} // Domain without port now
	results, err := ranker.TestAndRank(context.Background(), fingerprints, canaryDomains)
	if err != nil {
		t.Fatalf("TestAndRank failed: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("Expected 3 results, got %d", len(results))
	}

	if !results[0].Success || results[0].Fingerprint.ID != "fp1" {
		t.Errorf("Expected fp1 to be the best ranked, but got %s (success: %v)", results[0].Fingerprint.ID, results[0].Success)
	}

	if !results[1].Success || results[1].Fingerprint.ID != "fp2" {
		t.Errorf("Expected fp2 to be the second best, but got %s (success: %v)", results[1].Fingerprint.ID, results[1].Success)
	}

	if results[2].Success || results[2].Fingerprint.ID != "fp3" {
		t.Errorf("Expected fp3 to be the last and failed, but got %s (success: %v)", results[2].Fingerprint.ID, results[2].Success)
	}
}
