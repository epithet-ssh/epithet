package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/alecthomas/kong"
	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/lmittmann/tint"
)

const CA_PUBKEY = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF/w2nSKNmMMEWHu9hPlNRclzsrIrxtBrlA7a+jmf/s4 test@example.com`

type RequestBody struct {
	Signature  string            `json:"signature"`
	Token      string            `json:"token"`
	Connection policy.Connection `json:"connection"`
}

type CLI struct {
	Verbose int `short:"v" type:"counter" help:"Increase verbosity (-v for debug, -vv for trace)"`

	Principals []string `help:"principals to assign (can be specified multiple times)" short:"p" required:"true"`
	Port       int      `help:"port to listen on" short:"P" default:"9999"`
}

var cli CLI

func (c *CLI) Run(logger *slog.Logger) error {
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
		conn := body.Connection

		err = ca.Verify(CA_PUBKEY, token, signature)
		if err != nil {
			w.Header().Add("Content/type", "text/plain")
			w.WriteHeader(400)
			w.Write([]byte("invalid token signature received from CA"))
			return
		}

		// Example policy decision based on connection
		// This is a "bad" policy that approves everything
		resp := &ca.PolicyResponse{
			CertParams: ca.CertParams{
				Identity:   "steve",
				Names:      cli.Principals,
				Expiration: time.Minute,
				Extensions: map[string]string{
					"permit-agent-forwarding": "",
					"permit-pty":              "",
					"permit-user-rc":          "",
				},
			},
			Policy: policy.Policy{
				// Match pattern based on the connection's remote host
				// In a real policy server, this would be determined by business logic
				HostPattern: "*",
			},
		}

		out, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			w.Header().Add("Content/type", "text/plain")
			w.WriteHeader(500)
			w.Write([]byte(fmt.Sprintf("%v", err)))
			return
		}

		// Log the connection info for demonstration
		logger.Info("policy request",
			"remote_user", conn.RemoteUser,
			"remote_host", conn.RemoteHost,
			"port", conn.Port,
			"hash", conn.Hash)

		w.Header().Add("Content/type", "application/json")
		w.WriteHeader(200)
		w.Write(out)
	}))

	addr := fmt.Sprintf(":%d", cli.Port)
	logger.Info("starting bad-policy server", "addr", addr, "principals", cli.Principals)
	return http.ListenAndServe(addr, r)
}

func main() {
	ktx := kong.Parse(&cli)
	logger := setupLogger()
	ktx.Bind(logger)
	err := ktx.Run()
	if err != nil {
		logger.Error("error", "error", err)
		os.Exit(1)
	}
}

func setupLogger() *slog.Logger {
	// Determine log level based on verbosity
	level := slog.LevelWarn
	switch cli.Verbose {
	case 0:
		level = slog.LevelWarn
	case 1:
		level = slog.LevelInfo
	default: // 2 or more
		level = slog.LevelDebug
	}

	logger := slog.New(tint.NewHandler(os.Stderr, &tint.Options{
		Level:      level,
		TimeFormat: "15:04:05",
	}))

	return logger
}
