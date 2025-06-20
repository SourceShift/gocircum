package ranker

import (
	"context"
	"fmt"
	"testing"
	"time"

	"net"
	"net/http"
	"os"

	"github.com/gocircum/gocircum/core/config"
	"github.com/gocircum/gocircum/core/engine"
	"github.com/gocircum/gocircum/testutils"
	"go.uber.org/mock/gomock"
)

// TestMain manages test execution and cleanup to prevent goroutine leaks
func TestMain(m *testing.M) {
	// Run the tests
	code := m.Run()

	// Force cleanup of any lingering goroutines or resources
	http.DefaultClient.CloseIdleConnections()
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()

	// Give any lingering goroutines a chance to clean up
	time.Sleep(100 * time.Millisecond)

	// Exit with the test status code
	os.Exit(code)
}

// mockResolver implements the DNSResolver interface for testing.
type mockResolver struct{}

func (m *mockResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	if name == "www.example.com" {
		return ctx, net.ParseIP("1.2.3.4"), nil
	}
	return ctx, nil, fmt.Errorf("domain not found in mock resolver: %s", name)
}

// mockDialer simulates network dialing for tests.
func mockDialer(t *testing.T, ctrl *gomock.Controller, succeedDial bool, succeedHTTP bool, delay time.Duration, expectedAddr string) engine.Dialer {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != expectedAddr {
			t.Helper()
			t.Errorf("dialer called with wrong address: got %s, want %s", address, expectedAddr)
			return nil, fmt.Errorf("unexpected address for dialer: %s", address)
		}

		if succeedDial {
			time.Sleep(delay)
			conn := testutils.NewMockConn(ctrl)
			conn.EXPECT().SetDeadline(gomock.Any()).Return(nil).AnyTimes()
			conn.EXPECT().Close().Return(nil).AnyTimes()

			if succeedHTTP {
				// Expect Write to be called with any byte slice - we're using AnyTimes()
				// to allow for multiple writes in the HTTP exchange
				conn.EXPECT().Write(gomock.Any()).DoAndReturn(func(b []byte) (int, error) {
					return len(b), nil
				}).AnyTimes()

				// Expect Read to be called and return a valid HTTP response
				httpResponse := []byte("HTTP/1.1 200 OK\r\n\r\nHello")
				conn.EXPECT().Read(gomock.Any()).DoAndReturn(func(b []byte) (int, error) {
					copy(b, httpResponse)
					return len(httpResponse), nil
				}).AnyTimes()
			} else {
				// Simulate a failure during the HTTP exchange
				conn.EXPECT().Write(gomock.Any()).Return(0, fmt.Errorf("write error")).AnyTimes()
				// Add a Read expectation for any attempts to read after failure
				conn.EXPECT().Read(gomock.Any()).Return(0, fmt.Errorf("read error after write failure")).AnyTimes()
			}

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
	case "fp1": // Succeeds fast
		return mockDialer(f.t, f.ctrl, true, true, 50*time.Millisecond, expectedAddr), nil
	case "fp2": // Succeeds slow
		return mockDialer(f.t, f.ctrl, true, true, 150*time.Millisecond, expectedAddr), nil
	case "fp3": // Fails to dial
		return mockDialer(f.t, f.ctrl, false, false, 0, expectedAddr), nil
	case "fp4": // Dials, but HTTP exchange fails
		return mockDialer(f.t, f.ctrl, true, false, 20*time.Millisecond, expectedAddr), nil
	default: // Fails to dial by default
		return mockDialer(f.t, f.ctrl, false, false, 0, expectedAddr), nil
	}
}

func TestRanker_TestAndRank(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	logger := testutils.NewTestLogger()
	// Provide a dummy provider to satisfy the NewRanker validation,
	// as we are injecting a mock resolver for this test anyway.
	dummyProviders := []config.DoHProvider{{Name: "dummy", URL: "dummy"}}
	ranker, err := NewRanker(logger, dummyProviders)
	if err != nil {
		t.Fatalf("NewRanker failed unexpectedly: %v", err)
	}
	ranker.DialerFactory = &mockDialerFactory{t: t, ctrl: ctrl} // Inject the mock factory
	ranker.DoHResolver = &mockResolver{}                        // Inject the mock resolver

	fingerprints := []*config.Fingerprint{
		{ID: "fp1", TLS: config.TLS{ClientHelloID: "fp1"}}, // Succeeds fast
		{ID: "fp2", TLS: config.TLS{ClientHelloID: "fp2"}}, // Succeeds slow
		{ID: "fp3", TLS: config.TLS{ClientHelloID: "fp3"}}, // Should fail dial
		{ID: "fp4", TLS: config.TLS{ClientHelloID: "fp4"}}, // Should fail http
	}

	canaryDomains := []string{"www.example.com"}
	// Create a context that tells the ranker this is a test run
	testCtx := context.WithValue(context.Background(), testContextKey, true)
	results, err := ranker.TestAndRank(testCtx, fingerprints, canaryDomains)
	if err != nil {
		t.Fatalf("TestAndRank failed: %v", err)
	}

	if len(results) != 4 {
		t.Fatalf("Expected 4 results, got %d", len(results))
	}

	// Because we disabled shuffling and expansion for the test, the order should be deterministic.
	if !results[0].Success || results[0].Fingerprint.ID != "fp1" {
		t.Errorf("Expected fp1 to be the best ranked, but got %s (success: %v)", results[0].Fingerprint.ID, results[0].Success)
	}
	if !results[1].Success || results[1].Fingerprint.ID != "fp2" {
		t.Errorf("Expected fp2 to be the second best, but got %s (success: %v)", results[1].Fingerprint.ID, results[1].Success)
	}

	// The remaining two results should be the failed strategies.
	failedResults := results[2:]
	foundFp3 := false
	foundFp4 := false
	for _, res := range failedResults {
		if res.Success {
			t.Errorf("Expected a failed strategy, but got a success for %s", res.Fingerprint.ID)
		}
		if res.Fingerprint.ID == "fp3" {
			foundFp3 = true
		}
		if res.Fingerprint.ID == "fp4" {
			foundFp4 = true
		}
	}

	if !foundFp3 {
		t.Errorf("Did not find failed result for fp3")
	}
	if !foundFp4 {
		t.Errorf("Did not find failed result for fp4")
	}
}
