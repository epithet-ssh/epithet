package broker

import (
	"sync"
	"time"

	"github.com/epithet-ssh/epithet/pkg/agent"
	"github.com/epithet-ssh/epithet/pkg/policy"
)

const (
	// expiryBuffer is the time buffer before certificate expiration.
	// Certificates are considered expired this much time before their actual expiration
	// to account for:
	// - Socket setup and IPC delays (~100ms)
	// - SSH protocol negotiation and network transmission (~500ms-2s)
	// - Clock skew between client and server (±2s)
	// - General processing overhead (~100ms)
	// With short-lived certificates (2+ minutes), this 5s buffer provides safety
	// without meaningfully reducing usability.
	expiryBuffer = 5 * time.Second
)

// PolicyCert combines a policy with its associated certificate and expiration.
type PolicyCert struct {
	Policy     policy.Policy
	Credential agent.Credential
	ExpiresAt  time.Time
}

// CertificateStore manages the mapping of policies to certificates.
//
// Concurrency: CertificateStore is safe for concurrent use.
// All public methods use internal locking (lock/RWMutex).
//
// Locking invariants:
//   - lock protects: certs slice (all reads and writes)
//   - Store() uses write lock (exclusive access)
//   - Lookup() uses write lock (not read lock) because it may modify the slice (removing expired certs)
type CertificateStore struct {
	lock  sync.RWMutex // Protects certs slice
	certs []PolicyCert // Protected by lock
}

// NewCertificateStore creates a new empty certificate store
func NewCertificateStore() *CertificateStore {
	return &CertificateStore{
		certs: make([]PolicyCert, 0),
	}
}

// Store adds a certificate for a given policy.
// No deduplication is performed - overlapping policies are fine and will coexist.
// Certificates expire naturally and are cleaned up during Lookup.
func (cs *CertificateStore) Store(pc PolicyCert) {
	cs.lock.Lock()
	defer cs.lock.Unlock()

	cs.certs = append(cs.certs, pc)
}

// Lookup finds a valid certificate for the given connection.
// Returns the Credential and true if found and not expired, otherwise returns false.
// Policies are evaluated in order; the first matching, non-expired certificate is returned.
// Expired certificates are removed from the store during lookup.
// Certificates are considered expired expiryBuffer seconds before their actual expiration time.
func (cs *CertificateStore) Lookup(conn policy.Connection) (agent.Credential, bool) {
	cs.lock.Lock()
	defer cs.lock.Unlock()

	now := time.Now().Add(expiryBuffer)

	for i := 0; i < len(cs.certs); i++ {
		pc := cs.certs[i]

		// Check if policy matches the connection
		if pc.Policy.Matches(conn) {
			// Check if certificate is still valid (with buffer)
			if now.Before(pc.ExpiresAt) {
				return pc.Credential, true
			}

			// Certificate is expired (or within buffer), remove it
			cs.certs = append(cs.certs[:i], cs.certs[i+1:]...)
			i-- // Adjust index after removal
		}
	}

	return agent.Credential{}, false
}

// List returns information about all stored certificates.
// Used by the inspect command to show broker state.
func (cs *CertificateStore) List() []CertInfo {
	cs.lock.RLock()
	defer cs.lock.RUnlock()

	result := make([]CertInfo, len(cs.certs))
	for i, pc := range cs.certs {
		result[i] = CertInfo{
			Certificate: pc.Credential.Certificate,
			Policy:      pc.Policy,
			ExpiresAt:   pc.ExpiresAt,
		}
	}
	return result
}
