package ranker

import (
	"context"
	"gocircum/core/config"
	"gocircum/core/engine"
	"gocircum/testutils"
	"net"
	"testing"
	"time"

	"go.uber.org/mock/gomock"
)

// mockDialer simulates network dialing for tests.
func mockDialer(ctrl *gomock.Controller, succeed bool, delay time.Duration) engine.Dialer {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
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
	ctrl *gomock.Controller
}

func (f *mockDialerFactory) NewDialer(transportCfg *config.Transport, tlsCfg *config.TLS) (engine.Dialer, error) {
	// This is a simplified mock. A more complex test could check cfg.
	// We'll determine behavior based on the fingerprint ID, which we'll pass
	// via the ClientHelloID field for convenience in this test.
	switch tlsCfg.ClientHelloID {
	case "fp1":
		return mockDialer(f.ctrl, true, 50*time.Millisecond), nil
	case "fp2":
		return mockDialer(f.ctrl, true, 150*time.Millisecond), nil
	default:
		return mockDialer(f.ctrl, false, 0), nil
	}
}

func TestRanker_TestAndRank(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	logger := testutils.NewTestLogger()
	ranker := NewRanker(logger)
	ranker.DialerFactory = &mockDialerFactory{ctrl: ctrl} // Inject the mock factory

	fingerprints := []*config.Fingerprint{
		{ID: "fp1", TLS: config.TLS{ClientHelloID: "fp1"}}, // Should succeed fast
		{ID: "fp2", TLS: config.TLS{ClientHelloID: "fp2"}}, // Should succeed slow
		{ID: "fp3", TLS: config.TLS{ClientHelloID: "fp3"}}, // Should fail
	}

	canaryDomains := []string{"www.example.com:443"}
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
