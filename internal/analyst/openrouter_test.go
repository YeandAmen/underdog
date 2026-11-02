package analyst_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/YeandAmen/underdog/internal/analyst"
	"github.com/YeandAmen/underdog/internal/config"
)

func TestOpenRouterUsesResponsesEndpointAndNamespacedModel(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		json.NewDecoder(r.Body).Decode(&payload)
		if r.URL.Path != "/api/v1/responses" || payload["model"] != "openai/gpt-6.1-sol" || r.Header.Get("X-OpenRouter-Title") != "Underdog" || r.Header.Get("Authorization") != "Bearer test-only-key" {
			t.Error("incorrect OpenRouter protocol or model identity")
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "completed", "output_text": "READY"})
	}))
	defer provider.Close()
	client := analyst.New(config.Config{AIProvider: "openrouter", AIBaseURL: provider.URL + "/api/v1", AIModel: "openai/gpt-6.1-sol", AIKey: "test-only-key"})
	if err := client.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
}
