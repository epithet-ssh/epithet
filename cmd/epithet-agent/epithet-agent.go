package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/brianm/epithet/internal/agent"
	"github.com/spf13/cobra"
)

func main() {
	cmd := &cobra.Command{
		Use:  "epithet-agent COMMAND",
		RunE: run,
	}
	err := cmd.Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v", err)
		os.Exit(1)
	}
}

func run(cc *cobra.Command, args []string) error {
	f, err := ioutil.TempFile("", "epithet-agent.*")
	if err != nil {
		return err
	}
	path := f.Name()
	f.Close()
	defer os.Remove(path)
	os.Remove(path)

	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("exiting")
		cancel()
	}()

	a, err := agent.Start(ctx, agent.Config{
		AuthSocketPath: path,
	})
	if err != nil {
		return fmt.Errorf("unable to start agent: %w", err)
	}

	err = a.UseCredential(agent.Credential{
		PrivateKey:  []byte(privateKey),
		Certificate: []byte(certificate),
	})
	if err != nil {
		return fmt.Errorf("unable to set credential on agent: %w", err)
	}

	bin, err := exec.LookPath(args[0])
	if err != nil {
		return fmt.Errorf("unable to locate command %s", args[0])
	}
	cmd := exec.Command(bin, args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.Env = fixEnv(path, os.Environ())

	err = cmd.Run()
	cancel()
	return err
}

func fixEnv(path string, env []string) []string {
	newEnv := []string{}
	for _, line := range env {
		if !strings.HasPrefix(line, "SSH_AUTH_SOCK=") {
			newEnv = append(newEnv, line)
		}
	}
	return append(newEnv, fmt.Sprintf("SSH_AUTH_SOCK=%s", path))
}

const privateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACD+94OTJVooGNj9LO4lPwobX9zIvisccuNeTpBMsQO+UgAAAJjcBY813AWP
NQAAAAtzc2gtZWQyNTUxOQAAACD+94OTJVooGNj9LO4lPwobX9zIvisccuNeTpBMsQO+Ug
AAAEC6GR1iGMhzhphbnsAIN44Wpn8AZzAQTWh/gdHaKzfOg/73g5MlWigY2P0s7iU/Chtf
3Mi+Kxxy415OkEyxA75SAAAAD2JyaWFubW5Ac2N1ZmZpbgECAwQFBg==
-----END OPENSSH PRIVATE KEY-----`

const certificate = `ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAID4AIPoWH60yQ3Ay6V9oYBBALFVszirLToisufG6hGaLAAAAIP73g5MlWigY2P0s7iU/Chtf3Mi+Kxxy415OkEyxA75SAAAAAAAAAAAAAAABAAAABmJyaWFubQAAAAoAAAAGYnJpYW5tAAAAAAAAAAD//////////wAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQDNH7zWoDN/0GHOqMq8E4l0xehxI4bqcqp4FmjMoGp1gb1VYl+G/KWoRufzamCvVvX37oGfTlIi/0wW/mCFPtVv9Dg6nWGVRz6rECv4hjF4TcxgXIXbVLw70Lwy0FNhc9bX13D+4Z8UkaP94c0s79nbtfW7w82jvnCXwWYh9odr+PX9tSZOCJvWgoGd0/pMbyLp/7EapGByu+fxqx4Xyb89RVtCpBBZrZ7xOqPV5wD5BjHfrCREqcdeV8jzzQkxDUclPjbFga4WWUMEFz3lr8b14yPl0m5ANCRFz2RX7jp8xKiL8gz7V0K37ZX5vHaGgaDHgQbmRvq7BkaGWRYELyzJAAABDwAAAAdzc2gtcnNhAAABALpCd/eBkQig/ap5wCJQEfx9xMhNMPa0Fn4+b2F80dHBKly9xZAM68h/sKIrJZe17xspFbe0gDNs7RkFtBnK6iLG5VZSNIzwsxGJ63J/w1DMrz1t1gJQNCDfzpznNJOc4MhcbF6HdF+kYA11DIN/lST1Th80l7EM9Q4NVChA5J2bDiSUso5oMN+RkUJRiCBjc6UG9BiJt3c3B2cUuvjSEtU/jRrR6sCH+klICOUSsscOToiFxjtsL4wmogMD+TS9e7CpgJBX8cxZP1pZ2bY5qik27llPS1YAtroEbE4OliqZQ35wLqHsmMYYg5LDTFhd+HOu1fGSaemeh92CaGvOyAQ= brianmn@scuffin`
