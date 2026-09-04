package broker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"

	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

// Request is one line of JSON sent by the client. Exactly one field is set.
type Request struct {
	Match   *policy.Connection `json:"match,omitempty"`
	Inspect *struct{}          `json:"inspect,omitempty"`
	Kill    *KillRequest       `json:"kill,omitempty"`
}

// Event is one line of JSON sent by the broker in response to a Request.
// For a Match request: zero or more Output events (auth progress, e.g. the
// auth-code+PKCE URL to visit) followed by exactly one Result event. For an
// Inspect request: exactly one Inspect event.
type Event struct {
	Output  string           `json:"output,omitempty"`
	Result  *MatchResponse   `json:"result,omitempty"`
	Inspect *InspectResponse `json:"inspect,omitempty"`
	Kill    *KillResponse    `json:"kill,omitempty"`
}

// eventWriter serializes Event writes to a single client connection. Auth
// progress (Output events, written from inside MatchWithUserOutput's call
// to the auth flow) and the terminal Result event share this connection;
// without the lock, two writes racing on the same net.Conn could interleave
// mid-line and corrupt the newline-framed stream for the client.
type eventWriter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (w *eventWriter) writeEvent(ev Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.enc.Encode(ev)
}

// Write implements io.Writer so eventWriter can be passed directly to
// MatchWithUserOutput as the auth user-output sink: every write from the
// auth flow becomes one Output event.
func (w *eventWriter) Write(p []byte) (int, error) {
	if err := w.writeEvent(Event{Output: string(p)}); err != nil {
		return 0, err
	}
	return len(p), nil
}

// serveProtocol accepts connections on l and handles one Request per
// connection until l stops accepting (typically because ctx was canceled
// and Close() closed the listener).
func (b *Broker) serveProtocol(ctx context.Context, l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return // Expected: shutdown closed the listener.
			default:
				b.log.Error("protocol accept error", "error", err)
				return
			}
		}

		b.activeRPC.Add(1)
		go func() {
			defer b.activeRPC.Done()
			defer conn.Close()
			b.handleConn(ctx, conn)
		}()
	}
}

// handleConn services a single client connection: read one Request line,
// dispatch it, write one or more Event lines back.
func (b *Broker) handleConn(ctx context.Context, conn net.Conn) {
	// Closing the connection (e.g. ssh gave up waiting on `epithet match`)
	// cancels connCtx, which abandons any in-flight auth/CA work started on
	// its behalf. This preserves the "client gave up -> stop working"
	// semantics the old gRPC stream context gave us for free via
	// stream.Context().
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 4096), wire.MaxBodySize)
	if !scanner.Scan() {
		return // Client disconnected before sending a request; nothing to answer.
	}

	w := &eventWriter{enc: json.NewEncoder(conn)}

	var req Request
	if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
		_ = w.writeEvent(Event{Result: &MatchResponse{
			Allow: false,
			Error: fmt.Sprintf("malformed request: %v", err),
		}})
		return
	}

	// The client sends exactly one request line and then only ever waits or
	// closes. Keep scanning in the background so a close is noticed (and
	// connCtx canceled) even while the request is still being handled below.
	go func() {
		for scanner.Scan() {
			// The client isn't expected to send more; ignore any of it.
		}
		cancel()
	}()

	switch {
	case req.Match != nil:
		result := b.MatchWithUserOutput(connCtx, *req.Match, w)
		_ = w.writeEvent(Event{Result: &result})
	case req.Inspect != nil:
		var resp InspectResponse
		if err := b.Inspect(InspectRequest{}, &resp); err != nil {
			_ = w.writeEvent(Event{Result: &MatchResponse{Allow: false, Error: err.Error()}})
			return
		}
		_ = w.writeEvent(Event{Inspect: &resp})
	case req.Kill != nil:
		resp := KillResponse{ID: req.Kill.ID}
		if err := b.Kill(*req.Kill, &resp); err != nil {
			resp.Error = err.Error()
		}
		_ = w.writeEvent(Event{Kill: &resp})
	default:
		_ = w.writeEvent(Event{Result: &MatchResponse{
			Allow: false,
			Error: "request must set exactly one of match, inspect, or kill",
		}})
	}
}
