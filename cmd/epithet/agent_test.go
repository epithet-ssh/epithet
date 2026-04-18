package main

import (
	"testing"
)

func TestReplaceEnv_ExistingKey(t *testing.T) {
	env := []string{"HOME=/home/user", "SSH_AUTH_SOCK=/old/path", "SHELL=/bin/fish"}
	result := replaceEnv(env, "SSH_AUTH_SOCK", "/new/path")

	found := false
	for _, e := range result {
		if e == "SSH_AUTH_SOCK=/new/path" {
			found = true
		}
		if e == "SSH_AUTH_SOCK=/old/path" {
			t.Error("old value still present")
		}
	}
	if !found {
		t.Error("new value not found")
	}
	if len(result) != 3 {
		t.Errorf("expected 3 entries, got %d", len(result))
	}
}

func TestReplaceEnv_NewKey(t *testing.T) {
	env := []string{"HOME=/home/user", "SHELL=/bin/fish"}
	result := replaceEnv(env, "SSH_AUTH_SOCK", "/new/path")

	found := false
	for _, e := range result {
		if e == "SSH_AUTH_SOCK=/new/path" {
			found = true
		}
	}
	if !found {
		t.Error("new key not appended")
	}
	if len(result) != 3 {
		t.Errorf("expected 3 entries, got %d", len(result))
	}
}

func TestReplaceEnv_EmptyEnv(t *testing.T) {
	result := replaceEnv(nil, "KEY", "value")
	if len(result) != 1 || result[0] != "KEY=value" {
		t.Errorf("expected [KEY=value], got %v", result)
	}
}
