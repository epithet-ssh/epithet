package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"io"
	"net/http"
)

type handler struct {
	woof        WoofFunc
	caPublicKey sshcert.RawPublicKey
}

type Status int

const (
	Ok Status = iota
	InvalidToken
	NotAuthorized
)

type WoofFunc func(context.Context, string) (Status, *ca.CertParams, error)

type Woof interface {
	GeneratePolicy(ctx context.Context, token string) (Status, *ca.CertParams, error)
}

func NewHandler(caPublicKey sshcert.RawPublicKey, woof Woof) http.Handler {
	return &handler{func(ctx context.Context, s string) (Status, *ca.CertParams, error) {
		return woof.GeneratePolicy(ctx, s)
	}, caPublicKey}
}

func NewHandlerFunc(caPublicKey sshcert.RawPublicKey, woof WoofFunc) http.Handler {
	return &handler{woof, caPublicKey}
}

func (f WoofFunc) GeneratePolicy(ctx context.Context, token string) (Status, *ca.CertParams, error) {
	return f(ctx, token)
}

func (p *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 8196))
	if err != nil {
		w.Header().Add("Content-type", "text/plain")
		w.WriteHeader(500)
		_, _ = fmt.Fprintf(w, "error reading body:\n%v", err)
		return
	}

	pr := ca.PolicyRequest{}
	err = json.Unmarshal(body, &pr)
	if err != nil {
		w.Header().Add("Content-type", "text/plain")
		w.WriteHeader(400)
		_, _ = fmt.Fprintf(w, "error parsing body:\n%v", err)
		return
	}

	err = ca.Verify(p.caPublicKey, pr.Token, pr.Signature)
	if err != nil {
		w.Header().Add("Content-type", "text/plain")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintf(w, "error processing signature:\n%v", err)
		return
	}

	status, params, err := p.woof.GeneratePolicy(context.Background(), pr.Token)
	if err != nil {
		w.Header().Add("Content-type", "text/plain")
		w.WriteHeader(500)
		_, _ = fmt.Fprintf(w, "error generating policy:\n%v", err)
		return
	}
	switch status {
	case Ok:
		out, err := json.Marshal(params)
		if err != nil {
			w.Header().Add("Content-type", "text/plain")
			w.WriteHeader(500)
			_, _ = fmt.Fprintf(w, "error marshalling policy parameters:\n%v", err)
			return
		}
		w.Header().Add("Content-type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(out)
	case InvalidToken:
		w.WriteHeader(http.StatusUnauthorized)
	case NotAuthorized:
		w.WriteHeader(http.StatusForbidden)
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}
}
