package transport

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

func TestTCPTransport_Dial(t *testing.T) {
	// Start a simple TCP echo server
	server, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}
	defer server.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := server.Accept()
		if err != nil {
			t.Logf("Server accept error: %v", err)
			return
		}
		defer conn.Close()
		io.CopyN(conn, conn, 5)
	}()

	// Create TCP transport
	transport, err := NewTCPTransport(&TCPConfig{
		DialTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to create TCP transport: %v", err)
	}

	// Dial the server
	conn, err := transport.DialContext(context.Background(), "tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	// Test the connection
	msg := []byte("hello")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	buf := make([]byte, 5)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if string(buf) != string(msg) {
		t.Errorf("Expected to read '%s', got '%s'", msg, buf)
	}

	wg.Wait()
}

func TestTCPTransport_DialTLS(t *testing.T) {
	// Generate a self-signed certificate for the test server
	cert, key, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}
	tlsCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatalf("Failed to create tls key pair: %v", err)
	}

	serverConfig := &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	server, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatalf("Failed to start TLS test server: %v", err)
	}
	defer server.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := server.Accept()
		if err != nil {
			t.Logf("Server accept error: %v", err)
			return
		}
		defer conn.Close()
		io.CopyN(conn, conn, int64(len("hello tls")))
	}()

	// Create TCP transport with TLS config
	clientConfig := &tls.Config{
		InsecureSkipVerify: true, // We use a self-signed cert
	}
	transport, err := NewTCPTransport(&TCPConfig{
		DialTimeout: time.Second,
		TLSConfig:   clientConfig,
	})
	if err != nil {
		t.Fatalf("Failed to create TCP transport: %v", err)
	}

	// Dial the TLS server
	conn, err := transport.DialContext(context.Background(), "tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	// Test the connection
	msg := []byte("hello tls")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if string(buf) != string(msg) {
		t.Errorf("Expected to read '%s', got '%s'", msg, buf)
	}

	wg.Wait()
}

func BenchmarkTCPTransport_Dial(b *testing.B) {
	server, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Failed to start test server: %v", err)
	}
	defer server.Close()
	go func() {
		for {
			conn, err := server.Accept()
			if err != nil {
				return // server closed
			}
			go func(c net.Conn) {
				defer c.Close()
				// Read one byte and close, to complete the client's request
				buf := make([]byte, 1)
				io.ReadFull(c, buf)
			}(conn)
		}
	}()

	transport, err := NewTCPTransport(&TCPConfig{
		DialTimeout: time.Second,
	})
	if err != nil {
		b.Fatalf("Failed to create TCP transport: %v", err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn, err := transport.DialContext(context.Background(), "tcp", server.Addr().String())
			if err != nil {
				// Don't fatal in a parallel benchmark
				b.Logf("Dial failed: %v", err)
				continue
			}
			if _, err := conn.Write([]byte("a")); err != nil {
				b.Logf("Write failed: %v", err)
			}
			conn.Close()
		}
	})
}

// generateTestCert creates a self-signed certificate and private key for testing.
func generateTestCert() (certPEM, keyPEM []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certBuf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBuf := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return certBuf, keyBuf, nil
}
