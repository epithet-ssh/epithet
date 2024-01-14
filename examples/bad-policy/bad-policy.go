package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

const CA_PUBKEY = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF/w2nSKNmMMEWHu9hPlNRclzsrIrxtBrlA7a+jmf/s4 test@example.com`

type RequestBody struct {
	Signature string `json:"signature"`
	Token     string `json:"token"`
}

func main() {
	r := chi.NewRouter()

	// A good base middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	r.Post("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, err := io.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}
		r.Body.Close()

		body := RequestBody{}
		err = json.Unmarshal(buf, &body)
		if err != nil {
			panic(err)
		}

		signature := body.Signature
		token := body.Token
		err = ca.Verify(CA_PUBKEY, token, signature)
		if err != nil {
			w.Header().Add("Content/type", "text/plain")
			w.WriteHeader(400)
			w.Write([]byte("invalid token signature received from CA"))
			return
		}

		out, err := json.MarshalIndent(&ca.CertParams{
			Identity:   "steve",
			Names:      []string{"pe", "brianm", "stl"},
			Expiration: time.Minute,
			Extensions: map[string]string{
				"permit-agent-forwarding": "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		}, "", "  ")
		if err != nil {
			w.Header().Add("Content/type", "text/plain")
			w.WriteHeader(500)
			w.Write([]byte(fmt.Sprintf("%v", err)))
			return
		}

		w.Header().Add("Content/type", "application/json")
		w.WriteHeader(200)
		w.Write(out)
	}))

	http.ListenAndServe(":9999", r)
}
