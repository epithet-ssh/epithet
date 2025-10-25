package broker

import (
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/agent"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/stretchr/testify/require"
)

func TestCertificateStore_BasicStoreAndLookup(t *testing.T) {
	store := NewCertificateStore()

	// Create a test certificate
	pc := PolicyCert{
		HostPattern: "*.example.com",
		Credential: agent.Credential{
			PrivateKey:  sshcert.RawPrivateKey("test-private-key"),
			Certificate: sshcert.RawCertificate("test-certificate"),
		},
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}

	// Store the certificate
	store.Store(pc)

	// Lookup should find it for matching hostname
	found, ok := store.Lookup("server.example.com")
	require.True(t, ok)
	require.Equal(t, pc.Credential, found)
}

func TestCertificateStore_PatternMatching(t *testing.T) {
	store := NewCertificateStore()

	pc := PolicyCert{
		HostPattern: "*.example.com",
		Credential: agent.Credential{
			PrivateKey:  sshcert.RawPrivateKey("test-key"),
			Certificate: sshcert.RawCertificate("test-cert"),
		},
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	store.Store(pc)

	tests := []struct {
		hostname string
		matches  bool
	}{
		{"server.example.com", true},
		{"api.example.com", true},
		{"example.com", false},      // No subdomain
		{"server.other.com", false}, // Different domain
		{"example.com.evil", false}, // Domain suffix doesn't match
	}

	for _, tt := range tests {
		t.Run(tt.hostname, func(t *testing.T) {
			_, ok := store.Lookup(tt.hostname)
			require.Equal(t, tt.matches, ok, "hostname: %s", tt.hostname)
		})
	}
}

func TestCertificateStore_ExpiredCertificate(t *testing.T) {
	store := NewCertificateStore()

	// Create an expired certificate
	pc := PolicyCert{
		HostPattern: "*.example.com",
		Credential: agent.Credential{
			PrivateKey:  sshcert.RawPrivateKey("test-key"),
			Certificate: sshcert.RawCertificate("test-cert"),
		},
		ExpiresAt: time.Now().Add(-1 * time.Minute), // Expired 1 minute ago
	}
	store.Store(pc)

	// Verify certificate is in store
	require.Len(t, store.certs, 1)

	// Lookup should not find expired certificate
	_, ok := store.Lookup("server.example.com")
	require.False(t, ok)

	// Expired certificate should have been removed
	require.Len(t, store.certs, 0)
}

func TestCertificateStore_ExpiryBuffer(t *testing.T) {
	store := NewCertificateStore()

	// Create a certificate that expires in 3 seconds (within the 5s buffer)
	pc := PolicyCert{
		HostPattern: "*.example.com",
		Credential: agent.Credential{
			PrivateKey:  sshcert.RawPrivateKey("test-key"),
			Certificate: sshcert.RawCertificate("test-cert"),
		},
		ExpiresAt: time.Now().Add(3 * time.Second),
	}
	store.Store(pc)

	// Lookup should not find certificate (within expiry buffer)
	_, ok := store.Lookup("server.example.com")
	require.False(t, ok)

	// Certificate should have been removed
	require.Len(t, store.certs, 0)
}

func TestCertificateStore_ValidWithBuffer(t *testing.T) {
	store := NewCertificateStore()

	// Create a certificate that expires in 10 seconds (outside the 5s buffer)
	pc := PolicyCert{
		HostPattern: "*.example.com",
		Credential: agent.Credential{
			PrivateKey:  sshcert.RawPrivateKey("test-key"),
			Certificate: sshcert.RawCertificate("test-cert"),
		},
		ExpiresAt: time.Now().Add(10 * time.Second),
	}
	store.Store(pc)

	// Lookup should find the certificate (outside buffer)
	found, ok := store.Lookup("server.example.com")
	require.True(t, ok)
	require.Equal(t, pc.Credential, found)

	// Certificate should still be in store
	require.Len(t, store.certs, 1)
}

func TestCertificateStore_UpdateExistingPattern(t *testing.T) {
	store := NewCertificateStore()

	// Store initial certificate
	pc1 := PolicyCert{
		HostPattern: "*.example.com",
		Credential: agent.Credential{
			PrivateKey:  sshcert.RawPrivateKey("old-key"),
			Certificate: sshcert.RawCertificate("old-cert"),
		},
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	store.Store(pc1)

	// Update with new certificate for same pattern
	pc2 := PolicyCert{
		HostPattern: "*.example.com",
		Credential: agent.Credential{
			PrivateKey:  sshcert.RawPrivateKey("new-key"),
			Certificate: sshcert.RawCertificate("new-cert"),
		},
		ExpiresAt: time.Now().Add(20 * time.Minute),
	}
	store.Store(pc2)

	// Should get the updated certificate
	found, ok := store.Lookup("server.example.com")
	require.True(t, ok)
	require.Equal(t, pc2.Credential, found)

	// Should only have one entry in the store
	require.Len(t, store.certs, 1)
}

func TestCertificateStore_MultiplePatterns(t *testing.T) {
	store := NewCertificateStore()

	// Store certificates for different patterns
	pc1 := PolicyCert{
		HostPattern: "*.example.com",
		Credential: agent.Credential{
			PrivateKey:  sshcert.RawPrivateKey("example-key"),
			Certificate: sshcert.RawCertificate("example-cert"),
		},
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	store.Store(pc1)

	pc2 := PolicyCert{
		HostPattern: "bastion-*",
		Credential: agent.Credential{
			PrivateKey:  sshcert.RawPrivateKey("bastion-key"),
			Certificate: sshcert.RawCertificate("bastion-cert"),
		},
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	store.Store(pc2)

	// Lookup for example.com pattern
	found, ok := store.Lookup("api.example.com")
	require.True(t, ok)
	require.Equal(t, "example-key", string(found.PrivateKey))

	// Lookup for bastion pattern
	found, ok = store.Lookup("bastion-prod")
	require.True(t, ok)
	require.Equal(t, "bastion-key", string(found.PrivateKey))
}

func TestCertificateStore_FirstMatchWins(t *testing.T) {
	store := NewCertificateStore()

	// Store a broad pattern first
	pc1 := PolicyCert{
		HostPattern: "*.example.com",
		Credential: agent.Credential{
			PrivateKey:  sshcert.RawPrivateKey("broad-key"),
			Certificate: sshcert.RawCertificate("broad-cert"),
		},
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	store.Store(pc1)

	// Store a more specific pattern that would also match
	pc2 := PolicyCert{
		HostPattern: "api.example.com",
		Credential: agent.Credential{
			PrivateKey:  sshcert.RawPrivateKey("specific-key"),
			Certificate: sshcert.RawCertificate("specific-cert"),
		},
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	store.Store(pc2)

	// First matching pattern should win
	found, ok := store.Lookup("api.example.com")
	require.True(t, ok)
	require.Equal(t, "broad-key", string(found.PrivateKey))
}

func TestCertificateStore_NoMatch(t *testing.T) {
	store := NewCertificateStore()

	pc := PolicyCert{
		HostPattern: "*.example.com",
		Credential: agent.Credential{
			PrivateKey:  sshcert.RawPrivateKey("test-key"),
			Certificate: sshcert.RawCertificate("test-cert"),
		},
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	store.Store(pc)

	// Lookup for non-matching hostname
	_, ok := store.Lookup("server.other.com")
	require.False(t, ok)
}

func TestCertificateStore_EmptyStore(t *testing.T) {
	store := NewCertificateStore()

	// Lookup in empty store should return false
	_, ok := store.Lookup("any.hostname.com")
	require.False(t, ok)
}
