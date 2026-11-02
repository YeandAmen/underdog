package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
)

// configureWorker exchanges only the worker credential with Vercel. Model
// credentials continue to be loaded by the repo's OpenCode process.
func configureWorker(ctx context.Context, local map[string]string) error {
	token := local["UNDERDOG_WORKER_TOKEN"]
	if token == "" {
		var secret [32]byte
		if _, err := rand.Read(secret[:]); err != nil {
			return err
		}
		token = hex.EncodeToString(secret[:])
		file, err := os.OpenFile(".env", os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, writeErr := fmt.Fprintln(file, "\nUNDERDOG_WORKER_TOKEN="+token)
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	for _, entry := range []struct{ key, value, kind string }{
		{"UNDERDOG_WORKER_TOKEN", token, "secret"},
		{"UNDERDOG_AI_BACKEND", "worker", "config"},
	} {
		cmd := exec.CommandContext(ctx, "npx", "--yes", "vercel", "env", "add", entry.key, "--environment", "production", "--type", entry.kind, "--force", "--yes", "--scope", "fyield1")
		cmd.Stdin = bytes.NewBufferString(entry.value)
		if _, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("configure %s for the hosted worker: %w", entry.key, err)
		}
		fmt.Println("Configured server variable:", entry.key)
	}
	return nil
}
