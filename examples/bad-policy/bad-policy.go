package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/brianm/epithet/pkg/ca"
)

func main() {
	http.ListenAndServe(":9999", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out, err := json.MarshalIndent(&ca.CertParams{
			Identity:   "woof",
			Names:      []string{"root"},
			Expiration: time.Minute * 5,
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
}
