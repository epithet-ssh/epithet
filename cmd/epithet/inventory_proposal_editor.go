package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/inventory"
	"gopkg.in/yaml.v3"
)

var errCanceled = errors.New("canceled")

func readChoice(input *bufio.Reader, prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	line, err := input.ReadString('\n')
	if err == io.EOF {
		return "exit", nil
	}
	return strings.ToLower(strings.TrimSpace(line)), err
}

func editProposal(initial inventory.Proposal, input *bufio.Reader, validators ...func(inventory.Proposal) error) (inventory.Proposal, error) {
	data, err := yaml.Marshal(initial)
	if err != nil {
		return initial, err
	}
	f, err := os.CreateTemp("", "epithet-host-*.yaml")
	if err != nil {
		return initial, err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return initial, err
	}
	if err = f.Close(); err != nil {
		return initial, err
	}
	for {
		editor := os.Getenv("EDITOR")
		if editor == "" {
			editor = "vi"
		}
		var command *exec.Cmd
		if runtime.GOOS == "windows" {
			command = exec.Command("cmd.exe", "/C", editor+" \""+f.Name()+"\"")
		} else {
			command = exec.Command("/bin/sh", "-c", "exec "+editor+" \"$1\"", "epithet-editor", f.Name())
		}
		command.Stdin = os.Stdin
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		if err = command.Run(); err != nil {
			return initial, fmt.Errorf("editor exited unsuccessfully; no submission: %w", err)
		}
		data, err = os.ReadFile(f.Name())
		if err != nil {
			return initial, err
		}
		if len(bytesTrim(data)) == 0 {
			return initial, errCanceled
		}
		proposal, validation := inventory.ParseProposal(data)
		if validation == nil {
			for _, validate := range validators {
				if validation = validate(proposal); validation != nil {
					break
				}
			}
		}
		if validation != nil {
			fmt.Fprintln(os.Stderr, "Invalid host YAML:", validation)
			choice, e := readChoice(input, "edit / [cancel: default on Enter]: ")
			if e != nil {
				return initial, e
			}
			if choice == "e" || choice == "edit" {
				continue
			}
			return initial, errCanceled
		}
		return proposal, nil
	}
}

func bytesTrim(data []byte) []byte { return []byte(strings.TrimSpace(string(data))) }
