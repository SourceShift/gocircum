package transport

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestFragmentationMiddleware(t *testing.T) {
	const fragmentSize = 5
	const fragmentDelay = 1 * time.Millisecond
	message := "hello world this is a test"

	var wg sync.WaitGroup
	wg.Add(1)

	// Create a listener that will receive the fragmented packets
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer func() { _ = listener.Close() }()

	var receivedData bytes.Buffer
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			t.Errorf("Accept failed: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()

		buf := make([]byte, fragmentSize)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if err == io.EOF {
					break
				}
				t.Errorf("Read failed: %v", err)
				return
			}
			receivedData.Write(buf[:n])
		}
	}()

	// Create a base TCP transport
	baseTransport, err := NewTCPTransport(&TCPConfig{})
	if err != nil {
		t.Fatalf("Failed to create TCP transport: %v", err)
	}

	// Wrap it with the fragmentation middleware
	fragMW := FragmentationMiddleware(fragmentSize, fragmentDelay)
	wrappedTransport := fragMW(baseTransport)

	// Parse the address into IP and port
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("Could not convert to TCPAddr: %v", listener.Addr())
	}

	conn, err := wrappedTransport.DialContext(context.Background(), "tcp", tcpAddr.IP, tcpAddr.Port)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_, err = conn.Write([]byte(message))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Give the server time to read all data
	_ = conn.Close()
	wg.Wait()

	if receivedData.String() != message {
		t.Errorf("Expected to receive '%s', but got '%s'", message, receivedData.String())
	}
}
