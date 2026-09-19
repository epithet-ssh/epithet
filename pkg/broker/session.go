package broker

import "context"

// TokenFactory creates an independent, initially unauthenticated token fetcher.
// It must not perform authentication or other blocking work. Each fetcher owns
// its refresh state; replacing it on logout drops that state along with Auth's
// ID token cache, even if a canceled fetch from the old session finishes late.
type TokenFactory func() TokenFunc

type authSession struct {
	auth   *Auth
	ctx    context.Context
	cancel context.CancelFunc
}

func newAuthSession(factory TokenFactory) *authSession {
	ctx, cancel := context.WithCancel(context.Background())
	return &authSession{auth: NewAuth(factory()), ctx: ctx, cancel: cancel}
}

// sessionRequest binds work to the login session it started in. Logout cancels
// its wait on authentication and its remote calls without holding the broker
// lock across either. Agent installation also checks session ownership under
// that lock so a late CA response cannot restore a logged-out credential.
func (b *Broker) sessionRequest(parent context.Context) (*authSession, context.Context, context.CancelFunc) {
	b.lock.Lock()
	session := b.session
	b.lock.Unlock()
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(session.ctx, cancel)
	if session.ctx.Err() != nil {
		cancel()
	}
	return session, ctx, func() { stop(); cancel() }
}

// LogoutResponse reports how many per-connection agents were cleared.
type LogoutResponse struct {
	AgentsCleared int    `json:"agentsCleared"`
	Error         string `json:"error,omitempty"`
}

// Logout clears this broker's login state and certificate agents. The broker
// stays running, ready to authenticate again on the next request. It does not
// sign out the browser, revoke certificates, or disconnect established SSH
// sessions. Repeated logout is safe and does not require authentication.
func (b *Broker) Logout() LogoutResponse {
	b.lock.Lock()
	defer b.lock.Unlock()
	if b.session.ctx.Err() != nil {
		return LogoutResponse{Error: "broker is closed"}
	}
	b.session.cancel()
	response := LogoutResponse{AgentsCleared: len(b.agents)}
	for id, entry := range b.agents {
		entry.agent.Close()
		delete(b.agents, id)
	}
	b.session = newAuthSession(b.newToken)
	return response
}
