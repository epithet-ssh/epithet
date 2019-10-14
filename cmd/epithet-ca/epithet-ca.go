package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"
	"goji.io"
	"goji.io/pat"
)

func main() {
	cmd := &cobra.Command{
		Use:  "epithet-ca",
		RunE: run,
	}
	err := cmd.Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v", err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	mux := goji.NewMux()
	mux.HandleFunc(pat.Get("/:name"), hello)
	return http.ListenAndServe("localhost:8888", mux)
}

func hello(w http.ResponseWriter, r *http.Request) {
	name := pat.Param(r, "name")
	fmt.Fprintf(w, "Hello, %s!", name)
}
