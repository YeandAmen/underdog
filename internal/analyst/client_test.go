package analyst_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/YeandAmen/identityshield/internal/analyst"
	"github.com/YeandAmen/identityshield/internal/config"
	"github.com/YeandAmen/identityshield/internal/domain"
)

func TestResponsesProtocolAndGroundTruthRedaction(t *testing.T) {
	events := []domain.Event{{ID: "EVT-1", Timestamp: time.Now(), Actor: "user", Host: "host", Kind: "process", Label: "malicious", Raw: "DO_NOT_SEND_RAW", Data: map[string]string{"password": "DO_NOT_SEND_PASSWORD", "ground_truth_origin": "DO_NOT_SEND_TRUTH", "command": "observed command"}}}
	incident := domain.Incident{ID: "CASE-1", EventIDs: []string{"EVT-1"}, EvidenceHash: "digest"}
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" || r.Header.Get("Authorization") != "Bearer test-only-key" {
			t.Error("incorrect Responses API path or authentication")
		}
		raw, _ := io.ReadAll(r.Body)
		for _, sentinel := range []string{"DO_NOT_SEND_RAW", "DO_NOT_SEND_PASSWORD", "DO_NOT_SEND_TRUTH", `\"label\":`} {
			if strings.Contains(string(raw), sentinel) {
				t.Errorf("private field leaked into model input: %s", sentinel)
			}
		}
		var request map[string]any
		json.Unmarshal(raw, &request)
		if request["model"] != "gpt-6.1-sol" {
			t.Error("the requested model was substituted")
		}
		report, _ := json.Marshal(domain.Report{Summary: "Observed process activity.", Verdict: "suspicious", Claims: []domain.Claim{{Text: "The process ran on the observed host.", EvidenceIDs: []string{"EVT-1"}}}, NextSteps: []string{"Validate the operator."}, Limitations: []string{"No independent process intent evidence."}})
		json.NewEncoder(w).Encode(map[string]any{"status": "completed", "output": []any{map[string]any{"type": "message", "content": []any{map[string]string{"type": "output_text", "text": string(report)}}}}})
	}))
	defer provider.Close()
	client := analyst.New(config.Config{AIProvider: "agentrouter", AIModel: "gpt-6.1-sol", AIBaseURL: provider.URL + "/v1", AIKey: "test-only-key"})
	report, err := client.Report(context.Background(), incident, events)
	if err != nil || report.Provider != "agentrouter" || report.EvidenceHash != "digest" {
		t.Fatalf("report protocol failed: %#v %v", report, err)
	}
}

func TestInventedCitationIsRejected(t *testing.T) {
	report := domain.Report{Summary: "Summary", Verdict: "suspicious", Claims: []domain.Claim{{Text: "Unsupported", EvidenceIDs: []string{"invented"}}}, NextSteps: []string{"Review"}, Limitations: []string{"Limited context"}}
	if err := analyst.Validate(report, []domain.Event{{ID: "real"}}); err == nil {
		t.Fatal("model-invented evidence was accepted")
	}
}
