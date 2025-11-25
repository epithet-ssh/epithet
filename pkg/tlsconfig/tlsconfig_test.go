package tlsconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func generateTestCACert(t *testing.T) []byte {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func TestNewHTTPClient_Default(t *testing.T) {
	cfg := Config{}
	client, err := NewHTTPClient(cfg)
	if err != nil {
		t.Fatalf("NewHTTPClient failed: %v", err)
	}
	if client == nil {
		t.Fatal("NewHTTPClient returned nil client")
	}
	if client.Timeout != DefaultTimeout {
		t.Errorf("expected timeout %v, got %v", DefaultTimeout, client.Timeout)
	}
}

func TestNewHTTPClient_Insecure(t *testing.T) {
	cfg := Config{Insecure: true}
	client, err := NewHTTPClient(cfg)
	if err != nil {
		t.Fatalf("NewHTTPClient failed: %v", err)
	}
	if client == nil {
		t.Fatal("NewHTTPClient returned nil client")
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport is not *http.Transport")
	}
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be true")
	}
}

func TestNewHTTPClient_CustomCA(t *testing.T) {
	// Create a temporary CA cert file
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")

	// Generate a self-signed CA certificate for testing
	caCert := generateTestCACert(t)

	if err := os.WriteFile(caFile, caCert, 0644); err != nil {
		t.Fatalf("failed to write CA cert file: %v", err)
	}

	cfg := Config{CACertFile: caFile}
	client, err := NewHTTPClient(cfg)
	if err != nil {
		t.Fatalf("NewHTTPClient failed: %v", err)
	}
	if client == nil {
		t.Fatal("NewHTTPClient returned nil client")
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport is not *http.Transport")
	}
	if transport.TLSClientConfig.RootCAs == nil {
		t.Error("expected RootCAs to be set")
	}
}

func TestNewHTTPClient_InvalidCAFile(t *testing.T) {
	cfg := Config{CACertFile: "/nonexistent/ca.pem"}
	_, err := NewHTTPClient(cfg)
	if err == nil {
		t.Fatal("expected error for nonexistent CA file")
	}
}

func TestNewHTTPClient_InvalidCACert(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "invalid.pem")

	if err := os.WriteFile(caFile, []byte("not a valid certificate"), 0644); err != nil {
		t.Fatalf("failed to write invalid cert file: %v", err)
	}

	cfg := Config{CACertFile: caFile}
	_, err := NewHTTPClient(cfg)
	if err == nil {
		t.Fatal("expected error for invalid CA cert")
	}
}

func TestValidateURL_HTTPS(t *testing.T) {
	cfg := Config{Insecure: false}
	err := cfg.ValidateURL("https://example.com")
	if err != nil {
		t.Errorf("expected no error for https URL, got: %v", err)
	}
}

func TestValidateURL_HTTP_WithInsecure(t *testing.T) {
	cfg := Config{Insecure: true}
	err := cfg.ValidateURL("http://example.com")
	if err != nil {
		t.Errorf("expected no error for http URL with insecure=true, got: %v", err)
	}
}

func TestValidateURL_HTTP_WithoutInsecure(t *testing.T) {
	cfg := Config{Insecure: false}
	err := cfg.ValidateURL("http://example.com")
	if err == nil {
		t.Error("expected error for http URL with insecure=false")
	}
}
