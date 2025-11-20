package broker

import (
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/agent"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/stretchr/testify/require"
)

func TestCertificateStore_BasicStoreAndLookup(t *testing.T) {
	store := NewCertificateStore()

	// Create a test certificate
	pc := PolicyCert{
		Policy: policy.Policy{HostUsers: map[string][]string{
			"*.example.com": {"alice", "bob"},
		}},
		Credential: agent.Credential{
			PrivateKey:  sshcert.RawPrivateKey("test-private-key"),
			Certificate: sshcert.RawCertificate("test-certificate"),
		},
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}

	// Store the certificate
	store.Store(pc)

	// Lookup should find it for matching hostname and user
	found, ok := store.Lookup(policy.Connection{RemoteHost: "server.example.com", RemoteUser: "alice"})
	require.True(t, ok)
	require.Equal(t, pc.Credential, found)

	// Lookup should also find it for bob
	found, ok = store.Lookup(policy.Connection{RemoteHost: "server.example.com", RemoteUser: "bob"})
	require.True(t, ok)
	require.Equal(t, pc.Credential, found)

	// Lookup should NOT find it for charlie (not in user list)
	_, ok = store.Lookup(policy.Connection{RemoteHost: "server.example.com", RemoteUser: "charlie"})
	require.False(t, ok)
}

func TestCertificateStore_PatternMatching(t *testing.T) {
	store := NewCertificateStore()

	pc := PolicyCert{
		Policy: policy.Policy{HostUsers: map[string][]string{
			"*.example.com": {"alice"},
		}},
		Credential: agent.Credential{
			PrivateKey:  sshcert.RawPrivateKey("test-key"),
			Certificate: sshcert.RawCertificate("test-cert"),
		},
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	store.Store(pc)

	tests := []struct {
		hostname string
		user     string
		matches  bool
	}{
		{"server.example.com", "alice", true},
		{"api.example.com", "alice", true},
		{"example.com", "alice", false},      // No subdomain
		{"server.other.com", "alice", false}, // Different domain
		{"example.com.evil", "alice", false}, // Domain suffix doesn't match
		{"server.example.com", "bob", false}, // Wrong user
	}

	for _, tt := range tests {
		t.Run(tt.hostname+"_"+tt.user, func(t *testing.T) {
			_, ok := store.Lookup(policy.Connection{RemoteHost: tt.hostname, RemoteUser: tt.user})
			require.Equal(t, tt.matches, ok, "hostname: %s, user: %s", tt.hostname, tt.user)
		})
	}
}

func TestCertificateStore_ExpiredCertificate(t *testing.T) {
	store := NewCertificateStore()

	// Create an expired certificate
	pc := PolicyCert{
		Policy: policy.Policy{HostUsers: map[string][]string{
			"*.example.com": {"alice"},
		}},
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
	_, ok := store.Lookup(policy.Connection{RemoteHost: "server.example.com", RemoteUser: "alice"})
	require.False(t, ok)

	// Expired certificate should have been removed
	require.Len(t, store.certs, 0)
}

func TestCertificateStore_ExpiryBuffer(t *testing.T) {
	store := NewCertificateStore()

	// Create a certificate that expires in 3 seconds (within the 5s buffer)
	pc := PolicyCert{
		Policy: policy.Policy{HostUsers: map[string][]string{
			"*.example.com": {"alice"},
		}},
		Credential: agent.Credential{
			PrivateKey:  sshcert.RawPrivateKey("test-key"),
			Certificate: sshcert.RawCertificate("test-cert"),
		},
		ExpiresAt: time.Now().Add(3 * time.Second),
	}
	store.Store(pc)

	// Lookup should not find certificate (within expiry buffer)
	_, ok := store.Lookup(policy.Connection{RemoteHost: "server.example.com", RemoteUser: "alice"})
	require.False(t, ok)

	// Certificate should have been removed
	require.Len(t, store.certs, 0)
}

func TestCertificateStore_ValidWithBuffer(t *testing.T) {
	store := NewCertificateStore()

	// Create a certificate that expires in 10 seconds (outside the 5s buffer)
	pc := PolicyCert{
		Policy: policy.Policy{HostUsers: map[string][]string{
			"*.example.com": {"alice"},
		}},
		Credential: agent.Credential{
			PrivateKey:  sshcert.RawPrivateKey("test-key"),
			Certificate: sshcert.RawCertificate("test-cert"),
		},
		ExpiresAt: time.Now().Add(10 * time.Second),
	}
	store.Store(pc)

	// Lookup should find the certificate (outside buffer)
	found, ok := store.Lookup(policy.Connection{RemoteHost: "server.example.com", RemoteUser: "alice"})
	require.True(t, ok)
	require.Equal(t, pc.Credential, found)

	// Certificate should still be in store
	require.Len(t, store.certs, 1)
}

func TestCertificateStore_OverlappingPolicies(t *testing.T) {
	store := NewCertificateStore()

	// Store certificate for alice
	pc1 := PolicyCert{
		Policy: policy.Policy{HostUsers: map[string][]string{
			"*.example.com": {"alice"},
		}},
		Credential: agent.Credential{
			PrivateKey:  sshcert.RawPrivateKey("alice-key"),
			Certificate: sshcert.RawCertificate("alice-cert"),
		},
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	store.Store(pc1)

	// Store certificate for bob (overlapping host pattern)
	pc2 := PolicyCert{
		Policy: policy.Policy{HostUsers: map[string][]string{
			"*.example.com": {"bob"},
		}},
		Credential: agent.Credential{
			PrivateKey:  sshcert.RawPrivateKey("bob-key"),
			Certificate: sshcert.RawCertificate("bob-cert"),
		},
		ExpiresAt: time.Now().Add(20 * time.Minute),
	}
	store.Store(pc2)

	// Alice should get her certificate
	found, ok := store.Lookup(policy.Connection{RemoteHost: "server.example.com", RemoteUser: "alice"})
	require.True(t, ok)
	require.Equal(t, "alice-key", string(found.PrivateKey))

	// Bob should get his certificate
	found, ok = store.Lookup(policy.Connection{RemoteHost: "server.example.com", RemoteUser: "bob"})
	require.True(t, ok)
	require.Equal(t, "bob-key", string(found.PrivateKey))

	// Should have both entries in the store (no deduplication)
	require.Len(t, store.certs, 2)
}

func TestCertificateStore_MultiplePatterns(t *testing.T) {
	store := NewCertificateStore()

	// Store certificates for different patterns
	pc1 := PolicyCert{
		Policy: policy.Policy{HostUsers: map[string][]string{
			"*.example.com": {"alice"},
		}},
		Credential: agent.Credential{
			PrivateKey:  sshcert.RawPrivateKey("example-key"),
			Certificate: sshcert.RawCertificate("example-cert"),
		},
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	store.Store(pc1)

	pc2 := PolicyCert{
		Policy: policy.Policy{HostUsers: map[string][]string{
			"bastion-*": {"alice"},
		}},
		Credential: agent.Credential{
			PrivateKey:  sshcert.RawPrivateKey("bastion-key"),
			Certificate: sshcert.RawCertificate("bastion-cert"),
		},
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	store.Store(pc2)

	// Lookup for example.com pattern
	found, ok := store.Lookup(policy.Connection{RemoteHost: "api.example.com", RemoteUser: "alice"})
	require.True(t, ok)
	require.Equal(t, "example-key", string(found.PrivateKey))

	// Lookup for bastion pattern
	found, ok = store.Lookup(policy.Connection{RemoteHost: "bastion-prod", RemoteUser: "alice"})
	require.True(t, ok)
	require.Equal(t, "bastion-key", string(found.PrivateKey))
}

func TestCertificateStore_FirstMatchWins(t *testing.T) {
	store := NewCertificateStore()

	// Store a broad pattern first
	pc1 := PolicyCert{
		Policy: policy.Policy{HostUsers: map[string][]string{
			"*.example.com": {"alice"},
		}},
		Credential: agent.Credential{
			PrivateKey:  sshcert.RawPrivateKey("broad-key"),
			Certificate: sshcert.RawCertificate("broad-cert"),
		},
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	store.Store(pc1)

	// Store a more specific pattern that would also match
	pc2 := PolicyCert{
		Policy: policy.Policy{HostUsers: map[string][]string{
			"api.example.com": {"alice"},
		}},
		Credential: agent.Credential{
			PrivateKey:  sshcert.RawPrivateKey("specific-key"),
			Certificate: sshcert.RawCertificate("specific-cert"),
		},
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	store.Store(pc2)

	// First matching pattern should win
	found, ok := store.Lookup(policy.Connection{RemoteHost: "api.example.com", RemoteUser: "alice"})
	require.True(t, ok)
	require.Equal(t, "broad-key", string(found.PrivateKey))
}

func TestCertificateStore_NoMatch(t *testing.T) {
	store := NewCertificateStore()

	pc := PolicyCert{
		Policy: policy.Policy{HostUsers: map[string][]string{
			"*.example.com": {"alice"},
		}},
		Credential: agent.Credential{
			PrivateKey:  sshcert.RawPrivateKey("test-key"),
			Certificate: sshcert.RawCertificate("test-cert"),
		},
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	store.Store(pc)

	// Lookup for non-matching hostname
	_, ok := store.Lookup(policy.Connection{RemoteHost: "server.other.com", RemoteUser: "alice"})
	require.False(t, ok)

	// Lookup for non-matching user
	_, ok = store.Lookup(policy.Connection{RemoteHost: "server.example.com", RemoteUser: "bob"})
	require.False(t, ok)
}

func TestCertificateStore_EmptyStore(t *testing.T) {
	store := NewCertificateStore()

	// Lookup in empty store should return false
	_, ok := store.Lookup(policy.Connection{RemoteHost: "any.hostname.com"})
	require.False(t, ok)
}
