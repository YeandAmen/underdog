package opencodecli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/YeandAmen/underdog/internal/config"
)

// Complete runs the actual OpenCode CLI with its native JSON event protocol.
// Report sessions are isolated, tools are denied, and only validated report
// content is returned to Underdog's persistent store.
func Complete(ctx context.Context, c config.Config, system, input string, schema map[string]any) (string, error) {
	root, err := ProjectRoot()
	if err != nil {
		root = "."
	}
	base, err := filepath.Abs(filepath.Join(c.DataDir, "opencode"))
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(base, 0700); err != nil {
		return "", errors.New("could not prepare the model engine")
	}
	binary := c.OpenCodeBinary
	if binary == "" {
		binary, err = LocalBinary(root)
		if err != nil {
			binary, err = bundledBinary(base)
		}
	}
	if err != nil || binary == "" {
		return "", errors.New("the model engine is not installed; run npm install or build the bundled runtime")
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(base, "session-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	env, err := Environment(c, root)
	if err != nil {
		return "", err
	}
	settings := map[string]any{}
	for _, entry := range env {
		if text, ok := strings.CutPrefix(entry, "OPENCODE_CONFIG_CONTENT="); ok {
			if err := json.Unmarshal([]byte(text), &settings); err != nil {
				return "", err
			}
		}
	}
	settings["default_agent"] = "incident-analyst"
	settings["formatter"], settings["lsp"] = false, false
	settings["agent"] = map[string]any{"incident-analyst": map[string]any{
		"description": "Underdog's evidence-grounded incident analyst", "mode": "primary",
		"model": Model, "permission": "deny", "prompt": system,
	}}
	if schema == nil {
		provider := settings["provider"].(map[string]any)["underdog"].(map[string]any)
		model := provider["models"].(map[string]any)[ModelAlias].(map[string]any)
		model["limit"] = map[string]int{"context": 200000, "output": 512}
	}
	encoded, err := json.Marshal(settings)
	if err != nil {
		return "", err
	}
	env = overrideEnvironment(env, map[string]string{
		"OPENCODE_CONFIG_CONTENT": string(encoded), "OPENCODE_DISABLE_PROJECT_CONFIG": "1",
		"XDG_CONFIG_HOME": filepath.Join(dir, "config"), "XDG_DATA_HOME": filepath.Join(dir, "data"),
		"XDG_CACHE_HOME": filepath.Join(base, "cache"), "XDG_STATE_HOME": filepath.Join(dir, "state"),
		"HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "",
		"http_proxy": "", "https_proxy": "", "all_proxy": "",
	})
	if schema == nil {
		env = overrideEnvironment(env, map[string]string{"OPENCODE_EXPERIMENTAL_OUTPUT_TOKEN_MAX": "512"})
	}
	if schema != nil {
		encoded, err := json.Marshal(schema)
		if err != nil {
			return "", err
		}
		input += "\nReturn only JSON matching this report schema. Evidence IDs must be selected from its enum, never from permission-finding IDs:\n" + string(encoded)
	}
	output, diagnostics := &limitedOutput{}, &limitedOutput{}
	args := []string{"run", "--format", "json", "--agent", "incident-analyst", "--model", Model, "--title", "Underdog incident report"}
	if len(input) < 64<<10 {
		args = append(args, input)
	} else {
		path := filepath.Join(dir, "evidence.txt")
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			return "", err
		}
		args = append(args, "--file", path, "Generate the requested report from the supplied evidence attachment.")
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir, cmd.Env = dir, env
	cmd.WaitDelay = 3 * time.Second
	cmd.Stderr = diagnostics
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", errors.New("could not start the model engine")
	}
	type result struct {
		text string
		err  error
	}
	finished := make(chan result, 1)
	go func() {
		text, err := scanEvents(io.TeeReader(stdout, output), c)
		finished <- result{text, err}
	}()
	select {
	case response := <-finished:
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if response.err != nil {
			if diagnostics.String() != "" && output.String() == "" {
				return "", engineError(c, diagnostics.String())
			}
			return "", response.err
		}
		return response.text, nil
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		select {
		case response := <-finished:
			if response.err != nil && !strings.Contains(response.err.Error(), "completed report") {
				return "", response.err
			}
		default:
		}
		detail := diagnostics.String()
		if c.AIKey != "" {
			detail = strings.ReplaceAll(detail, c.AIKey, "[redacted]")
		}
		types, reasons := eventSummary(output.String())
		slog.Warn("opencode-run-timeout", "event_types", types, "finish_reasons", reasons, "output_bytes", len(output.String()), "diagnostic", detail[:min(800, len(detail))])
		return "", errors.New("model generation timed out or was interrupted")
	}
}

func eventSummary(output string) (map[string]int, []string) {
	types := map[string]int{}
	reasons := []string{}
	for _, line := range strings.Split(output, "\n") {
		var event struct {
			Type string `json:"type"`
			Part struct {
				Reason string `json:"reason"`
			} `json:"part"`
		}
		if json.Unmarshal([]byte(line), &event) == nil {
			types[event.Type]++
			if event.Part.Reason != "" {
				reasons = append(reasons, event.Part.Reason)
			}
		}
	}
	return types, reasons
}

func parseEvents(output string, c config.Config) (string, error) {
	return scanEvents(strings.NewReader(output), c)
}

func scanEvents(reader io.Reader, c config.Config) (string, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 2<<20)
	var text strings.Builder
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event struct {
			Type  string          `json:"type"`
			Error json.RawMessage `json:"error"`
			Part  struct {
				Text   string `json:"text"`
				Reason string `json:"reason"`
			} `json:"part"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return "", errors.New("the model engine returned invalid JSON events")
		}
		if event.Type == "error" {
			return "", engineError(c, string(event.Error))
		}
		if event.Type == "step_finish" && (event.Part.Reason == "length" || event.Part.Reason == "content-filter") {
			return "", errors.New("the model did not complete the report; partial output was rejected")
		}
		if event.Type == "step_finish" && event.Part.Reason == "unknown" && text.Len() == 0 {
			return "", errors.New("our model service returned an empty response for this server; its cloud API connection needs to be restored")
		}
		if event.Type == "text" {
			text.WriteString(event.Part.Text)
		}
		if event.Type == "step_finish" && event.Part.Reason == "stop" && text.Len() > 0 {
			return text.String(), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", errors.New("the model response exceeded its event-size limit")
	}
	return "", errors.New("the model did not return a completed report")
}

func engineError(c config.Config, detail string) error {
	var response struct {
		Message string `json:"message"`
		Data    struct {
			Message    string `json:"message"`
			StatusCode int    `json:"statusCode"`
		} `json:"data"`
	}
	if json.Unmarshal([]byte(detail), &response) == nil {
		if response.Data.StatusCode == http.StatusTooManyRequests {
			return errors.New("our model has reached its request limit; please retry shortly")
		}
		if response.Data.Message != "" {
			detail = response.Data.Message
		} else if response.Message != "" {
			detail = response.Message
		} else {
			detail = "the model engine rejected the request"
		}
	}
	if c.AIKey != "" {
		detail = strings.ReplaceAll(detail, c.AIKey, "[redacted]")
	}
	if c.AIModel != "" {
		detail = strings.ReplaceAll(detail, c.AIModel, "our model")
	}
	if strings.Contains(strings.ToLower(detail), "captcha") || strings.Contains(detail, "Unexpected token '<'") {
		return errors.New("our model service could not accept this server's request; please try again after service access is restored")
	}
	return fmt.Errorf("model engine request failed: %s", detail[:min(800, len(detail))])
}

func overrideEnvironment(env []string, values map[string]string) []string {
	result := []string{}
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if _, replaced := values[key]; !replaced {
			result = append(result, entry)
		}
	}
	for key, value := range values {
		result = append(result, key+"="+value)
	}
	return result
}

type limitedOutput struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (o *limitedOutput) Write(data []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if available := (2 << 20) - o.b.Len(); available > 0 {
		o.b.Write(data[:min(available, len(data))])
	}
	return len(data), nil
}

func (o *limitedOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.b.String()
}
