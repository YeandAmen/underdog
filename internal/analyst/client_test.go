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

	"github.com/YeandAmen/underdog/internal/analyst"
	"github.com/YeandAmen/underdog/internal/config"
	"github.com/YeandAmen/underdog/internal/domain"
)

func TestResponsesProtocolAndGroundTruthRedaction(t *testing.T) {
	events := []domain.Event{{ID: "EVT-1", Timestamp: time.Now(), Actor: "user", Host: "host", Kind: "process", Label: "malicious", Raw: "DO_NOT_SEND_RAW", Data: map[string]string{"password": "DO_NOT_SEND_PASSWORD", "ground_truth_origin": "DO_NOT_SEND_TRUTH", "command": "observed command"}}}
	incident := domain.Incident{ID: "CASE-1", EventIDs: []string{"EVT-1"}, EvidenceHash: "digest"}
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" || r.Header.Get("Authorization") != "Bearer test-only-key" {
			t.Error("incorrect Responses API path or authentication")
		}
		if r.UserAgent() != "opencode/1.1.0" {
			t.Error("Agent Router's required client identifier was omitted")
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
		if request["stream"] != false {
			t.Error("the JSON response protocol was not requested explicitly")
		}
		if input, _ := request["input"].(string); !strings.Contains(strings.ToLower(input), "json") {
			t.Error("Responses JSON mode requires json in input, not only instructions")
		}
		format := request["text"].(map[string]any)["format"].(map[string]any)
		if format["type"] != "json_schema" || format["strict"] != true {
			t.Error("report output was not constrained to the citation schema")
		}
		schema := format["schema"].(map[string]any)
		claims := schema["properties"].(map[string]any)["claims"].(map[string]any)
		citations := claims["items"].(map[string]any)["properties"].(map[string]any)["evidence_ids"].(map[string]any)
		ids := citations["items"].(map[string]any)["enum"].([]any)
		if len(ids) != 1 || ids[0] != "EVT-1" {
			t.Error("citation schema did not restrict IDs to supplied events")
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

func TestClientRejectionIsNotReportedAsAnInvalidKey(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"type":"unauthorized_client_error","error":{"message":"unauthorized client detected"}}`)
	}))
	defer provider.Close()
	client := analyst.New(config.Config{AIProvider: "agentrouter", AIModel: "gpt-6.1-sol", AIBaseURL: provider.URL + "/v1", AIKey: "test-only-key"})
	err := client.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "rejected the API client (HTTP 401)") || strings.Contains(err.Error(), "update the server-side API key") {
		t.Fatalf("client restriction was misdiagnosed: %v", err)
	}
}

func TestHTMLGatewayFailureIsDiagnosedWithoutExposingItsBody(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><head><title>Network access denied</title></head><body>DO_NOT_SHOW_BODY</body></html>`)
	}))
	defer provider.Close()
	client := analyst.New(config.Config{AIProvider: "agentrouter", AIModel: "gpt-6.1-sol", AIBaseURL: provider.URL + "/v1", AIKey: "test-only-key"})
	err := client.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Network access denied") || !strings.Contains(err.Error(), "HTTP 200") || strings.Contains(err.Error(), "DO_NOT_SHOW_BODY") {
		t.Fatalf("HTML response was not safely diagnosed: %v", err)
	}
}

func TestBadRequestDetailsRedactTheProviderCredential(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"error":{"message":"Unsupported request; credential test-only-key"}}`)
	}))
	defer provider.Close()
	client := analyst.New(config.Config{AIProvider: "agentrouter", AIModel: "gpt-6.1-sol", AIBaseURL: provider.URL + "/v1", AIKey: "test-only-key"})
	err := client.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Unsupported request") || strings.Contains(err.Error(), "test-only-key") {
		t.Fatalf("bad-request diagnostic leaked a credential or hid the reason: %v", err)
	}
}

func TestAliyunCaptchaIsNotReportedAsAnInvalidKey(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><meta name="aliyun_waf_aa" content="challenge"><div id="aliyunCaptcha"></div></html>`)
	}))
	defer provider.Close()
	client := analyst.New(config.Config{AIProvider: "agentrouter", AIModel: "gpt-6.1-sol", AIBaseURL: provider.URL + "/v1", AIKey: "test-only-key"})
	err := client.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "CAPTCHA") || strings.Contains(err.Error(), "update the server-side API key") {
		t.Fatalf("provider CAPTCHA was misdiagnosed: %v", err)
	}
}
