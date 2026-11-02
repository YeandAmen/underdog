package opencodecli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/YeandAmen/underdog/internal/config"
)

const Version = "1.19.5"

func ProjectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "opencode.json")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				return dir, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("run this command inside the Underdog repository")
		}
		dir = parent
	}
}

func LocalBinary(root string) (string, error) {
	if path := filepath.Join(root, "node_modules", "opencode-ai", "bin", "opencode.exe"); regularFile(path) {
		return path, nil
	}
	arch := map[string]string{"amd64": "x64", "arm64": "arm64"}[runtime.GOARCH]
	if arch == "" {
		return "", fmt.Errorf("OpenCode does not support %s", runtime.GOARCH)
	}
	for _, suffix := range []string{"", "-baseline", "-musl", "-baseline-musl"} {
		for _, name := range []string{"opencode", "opencode.exe"} {
			path := filepath.Join(root, "node_modules", "opencode-"+runtime.GOOS+"-"+arch+suffix, "bin", name)
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				return path, nil
			}
		}
	}
	return "", errors.New("project-local OpenCode is not installed; run npm install")
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func Environment(c config.Config, root string) ([]string, error) {
	model := "underdog/" + c.AIModel
	settings := map[string]any{
		"$schema": "https://opencode.ai/config.json", "model": model,
		"small_model": model, "share": "disabled", "autoupdate": false,
		"snapshot": false, "enabled_providers": []string{"underdog"},
		"provider": map[string]any{"underdog": map[string]any{
			"name": "Our model", "npm": "@ai-sdk/openai",
			"options": map[string]any{"baseURL": c.AIBaseURL, "apiKey": "{env:AGENT_ROUTER_API_KEY}", "timeout": 360000},
			"models": map[string]any{c.AIModel: map[string]any{
				"name": c.AIModel, "reasoning": true,
				"limit":   map[string]int{"context": 200000, "output": 16384},
				"options": map[string]any{"store": false},
			}},
		}},
	}
	encoded, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		values[key] = value
	}
	values["AGENT_ROUTER_API_KEY"] = c.AIKey
	values["OPENCODE_CONFIG_CONTENT"] = string(encoded)
	values["OPENCODE_PURE"] = "1"
	values["OPENCODE_DISABLE_DEFAULT_PLUGINS"] = "1"
	values["OPENCODE_DISABLE_MODELS_FETCH"] = "1"
	values["OPENCODE_DISABLE_LSP_DOWNLOAD"] = "1"
	values["OPENCODE_DISABLE_AUTOUPDATE"] = "1"
	values["OPENCODE_DISABLE_EXTERNAL_SKILLS"] = "1"
	values["OPENCODE_DISABLE_CLAUDE_CODE"] = "1"
	values["OPENCODE_EXPERIMENTAL_OUTPUT_TOKEN_MAX"] = "16384"
	values["NO_PROXY"] = "localhost,127.0.0.1," + values["NO_PROXY"]
	values["no_proxy"] = "localhost,127.0.0.1," + values["no_proxy"]
	values["PATH"] = filepath.Join(root, "node_modules", ".bin") + string(os.PathListSeparator) + values["PATH"]
	result := []string{}
	for key, value := range values {
		result = append(result, key+"="+value)
	}
	return result, nil
}

func Run(ctx context.Context, c config.Config, root string, args []string) error {
	binary, err := LocalBinary(root)
	if err != nil {
		return err
	}
	environment, err := Environment(c, root)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir, cmd.Env = root, environment
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func Terminal(ctx context.Context, c config.Config, root, command string) error {
	if _, err := LocalBinary(root); err != nil {
		return err
	}
	environment, err := Environment(c, root)
	if err != nil {
		return err
	}
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
		if runtime.GOOS == "windows" {
			shell = "powershell.exe"
		}
	}
	args := []string{"-i"}
	if runtime.GOOS == "windows" {
		args = []string{"-NoLogo"}
	}
	if command != "" {
		args = []string{"-c", command}
		if runtime.GOOS == "windows" {
			args = []string{"-NoLogo", "-Command", command}
		}
	}
	fmt.Printf("Underdog terminal · %s\nProject-local OpenCode %s · type opencode to start\n", root, Version)
	cmd := exec.CommandContext(ctx, shell, args...)
	cmd.Dir, cmd.Env = root, environment
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}
