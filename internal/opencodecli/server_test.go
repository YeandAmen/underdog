package opencodecli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/YeandAmen/underdog/internal/config"
)

func TestCredentialIsAnEnvironmentReferenceInOpenCodeConfiguration(t *testing.T) {
	const key = "private-test-model-key"
	env, err := Environment(config.Config{AIModel: "gpt-6.1-sol", AIBaseURL: "https://agentrouter.org/v1", AIKey: key}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var content string
	foundKey := false
	for _, entry := range env {
		if strings.HasPrefix(entry, "OPENCODE_CONFIG_CONTENT=") {
			content = strings.TrimPrefix(entry, "OPENCODE_CONFIG_CONTENT=")
		}
		foundKey = foundKey || entry == "AGENT_ROUTER_API_KEY="+key
	}
	if !foundKey || strings.Contains(content, key) {
		t.Fatal("model credential was missing or embedded into configuration")
	}
	var settings map[string]any
	if err := json.Unmarshal([]byte(content), &settings); err != nil {
		t.Fatal(err)
	}
	if settings["model"] != "underdog/gpt-6.1-sol" || settings["share"] != "disabled" {
		t.Fatal("the requested model or private-session setting was lost")
	}
}

func TestModelEngineErrorsDoNotExposeCredentials(t *testing.T) {
	c := config.Config{AIKey: "private-test-model-key"}
	err := engineError(c, "upstream failure using private-test-model-key")
	if strings.Contains(err.Error(), c.AIKey) || !strings.Contains(err.Error(), "[redacted]") {
		t.Fatal("model-engine error exposed a credential")
	}
}

func TestAPIErrorDisplaysOnlyItsMessage(t *testing.T) {
	err := engineError(config.Config{}, `{"name":"APIError","data":{"message":"Request rejected","statusCode":400,"responseHeaders":{"set-cookie":"PRIVATE_COOKIE"},"responseBody":"PRIVATE_BODY"}}`)
	if !strings.Contains(err.Error(), "Request rejected") || strings.Contains(err.Error(), "PRIVATE_") {
		t.Fatal("API error exposed response headers or its raw body")
	}
}

func TestJSONEventsReturnOnlyFinalText(t *testing.T) {
	text, err := parseEvents("{\"type\":\"step_start\"}\n{\"type\":\"text\",\"part\":{\"text\":\"READY\"}}\n{\"type\":\"step_finish\",\"part\":{\"reason\":\"stop\"}}\n", config.Config{})
	if err != nil || text != "READY" {
		t.Fatalf("CLI text response was not extracted: %q %v", text, err)
	}
}

func TestPartialCLIOutputIsRejected(t *testing.T) {
	_, err := parseEvents("{\"type\":\"text\",\"part\":{\"text\":\"partial\"}}\n{\"type\":\"step_finish\",\"part\":{\"reason\":\"length\"}}\n", config.Config{})
	if err == nil {
		t.Fatal("incomplete model output was accepted")
	}
}

func TestEmptyUnknownResponseStopsBeforeRetrying(t *testing.T) {
	_, err := parseEvents("{\"type\":\"step_start\"}\n{\"type\":\"step_finish\",\"part\":{\"reason\":\"unknown\"}}\n", config.Config{})
	if err == nil || !strings.Contains(err.Error(), "empty response") {
		t.Fatal("an empty provider stream was not rejected immediately")
	}
}
