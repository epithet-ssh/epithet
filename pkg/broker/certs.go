package broker

import (
	"path/filepath"
	"sync"
	"time"

	"github.com/epithet-ssh/epithet/pkg/agent"
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

// PolicyCert combines a policy pattern with its associated certificate and expiration.
type PolicyCert struct {
	// HostPattern is a glob pattern for matching remote hostnames (e.g., "*.example.com", "bastion-*")
	HostPattern string
	Credential  agent.Credential
	ExpiresAt   time.Time
}

// matches checks if this policy's pattern matches the given hostname
func (pc *PolicyCert) matches(hostname string) bool {
	matched, err := filepath.Match(pc.HostPattern, hostname)
	if err != nil {
		// Invalid pattern, no match
		return false
	}
	return matched
}

// CertificateStore manages the mapping of policies to certificates
type CertificateStore struct {
	lock  sync.RWMutex
	certs []PolicyCert
}

// NewCertificateStore creates a new empty certificate store
func NewCertificateStore() *CertificateStore {
	return &CertificateStore{
		certs: make([]PolicyCert, 0),
	}
}

// Store adds or updates a certificate for a given policy pattern.
// If a certificate already exists for this pattern, it is replaced.
func (cs *CertificateStore) Store(pc PolicyCert) {
	cs.lock.Lock()
	defer cs.lock.Unlock()

	// Check if we already have a certificate for this pattern
	for i := range cs.certs {
		if cs.certs[i].HostPattern == pc.HostPattern {
			// Replace existing certificate
			cs.certs[i] = pc
			return
		}
	}

	// Add new policy-certificate mapping
	cs.certs = append(cs.certs, pc)
}

// Lookup finds a valid certificate for the given hostname.
// Returns the Credential and true if found and not expired, otherwise returns false.
// Policies are evaluated in order; the first matching, non-expired certificate is returned.
// Expired certificates are removed from the store during lookup.
// Certificates are considered expired expiryBuffer seconds before their actual expiration time.
func (cs *CertificateStore) Lookup(hostname string) (agent.Credential, bool) {
	cs.lock.Lock()
	defer cs.lock.Unlock()

	now := time.Now().Add(expiryBuffer)

	for i := 0; i < len(cs.certs); i++ {
		pc := cs.certs[i]

		// Check if policy matches the hostname
		if pc.matches(hostname) {
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
