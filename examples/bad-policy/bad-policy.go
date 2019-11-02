package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/brianm/epithet/pkg/ca"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

func main() {
	r := chi.NewRouter()

	// A good base middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	r.Post("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, err := ioutil.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}
		r.Body.Close()

		body := map[string]string{}
		err = json.Unmarshal(buf, &body)
		if err != nil {
			panic(err)
		}

		out, err := json.MarshalIndent(&ca.CertParams{
			Identity:   body["token"],
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
