package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/YeandAmen/underdog/internal/config"
	"github.com/YeandAmen/underdog/internal/domain"
	"github.com/YeandAmen/underdog/internal/server"
)

func privateResearchWorkspace(t *testing.T) (*server.Server, *httptest.Server) {
	t.Helper()
	app, err := server.New(config.Config{Addr: "127.0.0.1:8787", DataDir: t.TempDir(), PublicAccess: true, AccessToken: "research-owner-token", WorkerToken: "report-worker-token", Demo: true, AIProvider: "local", AIModel: "evidence-template-v1", AIBaseURL: "https://agentrouter.org/v1"})
	if err != nil {
		t.Fatal(err)
	}
	event := domain.Event{ID: "PRIVATE_COLLECTION-malicious-1", Timestamp: time.Now().UTC(), Actor: "privacy-user", Host: "office-host", Kind: "process", Source: "PRIVATE_SOURCE", Label: "malicious", Raw: "PRIVATE_RAW_PAYLOAD", Data: map[string]string{"command": "powershell.exe -EncodedCommand controlled-marker", "password": "PRIVATE_PASSWORD", "schema": "PRIVATE_FEATURE_SCHEMA", "truth_label": "PRIVATE_TRUTH_LABEL", "original_event_id": "PRIVATE_ORIGINAL_ID"}}
	if _, err := app.Store.Import(context.Background(), domain.Dataset{ID: "PRIVATE_DATASET", Name: "PRIVATE_RESEARCH_FILE.csv", Source: "PRIVATE_SOURCE", SourceURL: "https://private.example/PRIVATE_RESEARCH", Format: "canonical"}, []domain.Event{event}); err != nil {
		app.Store.Close()
		t.Fatal(err)
	}
	if err := app.Store.PutReview(context.Background(), domain.Review{IncidentID: "PRIVATE_REVIEW", Reason: "PRIVATE_RESEARCH_NOTES", Reviewer: "PRIVATE_REVIEWER"}); err != nil {
		app.Store.Close()
		t.Fatal(err)
	}
	host := httptest.NewServer(app.Handler())
	t.Cleanup(func() { host.Close(); app.Store.Close() })
	return app, host
}

func privacyRequest(t *testing.T, host *httptest.Server, method, path, token string) (int, []byte) {
	t.Helper()
	request, err := http.NewRequest(method, host.URL+path, strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, raw
}

func TestPublicStateHidesResearchAndOwnerStateKeepsIt(t *testing.T) {
	_, host := privateResearchWorkspace(t)
	status, raw := privacyRequest(t, host, http.MethodGet, "/api/state", "")
	if status != http.StatusOK || bytes.Contains(raw, []byte("PRIVATE_")) {
		t.Fatal("the public workspace exposed private collection information")
	}
	var state map[string]json.RawMessage
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"datasets", "catalog", "models", "scenarios", "data_mode", "kaggle_configured"} {
		if _, present := state[key]; present {
			t.Errorf("public state exposed research field %q", key)
		}
	}
	if string(state["research_access"]) != "false" {
		t.Fatal("public state granted owner research access")
	}
	status, owner := privacyRequest(t, host, http.MethodGet, "/api/state", "research-owner-token")
	if status != http.StatusOK || !bytes.Contains(owner, []byte("PRIVATE_RESEARCH_FILE.csv")) || !bytes.Contains(owner, []byte(`"models"`)) || !bytes.Contains(owner, []byte(`"research_access":true`)) {
		t.Fatal("the owner's private research view was lost or altered")
	}
}

func TestPrivateResearchEndpointsRejectVisitorsAndWorkerCredentials(t *testing.T) {
	_, host := privateResearchWorkspace(t)
	for _, endpoint := range []struct{ method, path string }{
		{http.MethodGet, "/api/events"},
		{http.MethodGet, "/api/export/events"},
		{http.MethodGet, "/api/export/model/authentication"},
		{http.MethodGet, "/api/datasets/kaggle/files"},
		{http.MethodPost, "/api/datasets/import"},
		{http.MethodPost, "/api/datasets/fetch/otrf"},
		{http.MethodPost, "/api/datasets/reprocess/PRIVATE_DATASET"},
		{http.MethodPost, "/api/research/train"},
		{http.MethodPost, "/api/lab/replay"},
		{http.MethodPost, "/api/events/PRIVATE_COLLECTION-malicious-1/label"},
		{http.MethodPost, "/api/rules/IS-001"},
		{http.MethodPost, "/api/incidents/CASE-private/review"},
	} {
		for _, token := range []string{"", "incorrect-owner-token", "report-worker-token"} {
			status, raw := privacyRequest(t, host, endpoint.method, endpoint.path, token)
			if status != http.StatusUnauthorized || bytes.Contains(raw, []byte("PRIVATE_")) {
				t.Errorf("private %s %s was accessible: HTTP %d", endpoint.method, endpoint.path, status)
			}
		}
	}
	for _, path := range []string{"/datasets", "/research"} {
		status, _ := privacyRequest(t, host, http.MethodGet, path, "")
		if status != http.StatusNotFound {
			t.Errorf("public research page %s was not hidden", path)
		}
	}
	for _, path := range []string{"/api/events", "/api/export/events", "/api/export/model/authentication"} {
		status, raw := privacyRequest(t, host, http.MethodGet, path, "research-owner-token")
		if status != http.StatusOK || len(raw) == 0 {
			t.Errorf("owner cannot access %s: HTTP %d", path, status)
		}
	}
}

func TestPublicIncidentAndReportUseOpaqueCitationsWithoutRawResearch(t *testing.T) {
	_, host := privateResearchWorkspace(t)
	_, raw := privacyRequest(t, host, http.MethodGet, "/api/state", "")
	var state struct {
		Incidents []domain.Incident `json:"incidents"`
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	id := ""
	for _, incident := range state.Incidents {
		if incident.Actor == "privacy-user" {
			id = incident.ID
		}
	}
	if id == "" {
		t.Fatal("the private research fixture did not create an office alert")
	}
	_, raw = privacyRequest(t, host, http.MethodGet, "/api/incidents/"+id, "")
	if bytes.Contains(raw, []byte("PRIVATE_")) || bytes.Contains(raw, []byte(`"ground_truth"`)) {
		t.Fatal("public investigation exposed raw research or labels")
	}
	var info struct {
		Events []map[string]json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		t.Fatal(err)
	}
	for _, event := range info.Events {
		for _, key := range []string{"source", "dataset_id", "run_id", "label", "raw", "raw_sha256"} {
			if _, present := event[key]; present {
				t.Errorf("public event exposed %q", key)
			}
		}
	}
	status, reportRaw := privacyRequest(t, host, http.MethodPost, "/api/incidents/"+id+"/report", "")
	var report domain.Report
	if status != http.StatusOK || json.Unmarshal(reportRaw, &report) != nil || len(report.Claims) == 0 {
		t.Fatal("public report generation failed")
	}
	var eventID string
	json.Unmarshal(info.Events[0]["id"], &eventID)
	if !strings.HasPrefix(eventID, "EVT-") || report.Claims[0].EvidenceIDs[0] != eventID {
		t.Fatal("public citations no longer match displayed evidence")
	}
	status, markdown := privacyRequest(t, host, http.MethodGet, "/api/export/report/"+id, "")
	if status != http.StatusOK || bytes.Contains(markdown, []byte("PRIVATE_")) || !bytes.Contains(markdown, []byte(eventID)) {
		t.Fatal("public report export exposed private identifiers or lost citations")
	}
	_, ownerRaw := privacyRequest(t, host, http.MethodGet, "/api/incidents/"+id, "research-owner-token")
	if !bytes.Contains(ownerRaw, []byte("PRIVATE_RAW_PAYLOAD")) || !bytes.Contains(ownerRaw, []byte("PRIVATE_COLLECTION-malicious-1")) {
		t.Fatal("public redaction changed the owner's stored evidence")
	}
}
