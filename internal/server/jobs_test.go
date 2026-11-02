package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/YeandAmen/underdog/internal/config"
	"github.com/YeandAmen/underdog/internal/domain"
	"github.com/YeandAmen/underdog/internal/server"
	"github.com/YeandAmen/underdog/internal/worker"
)

func queuedWorkspace(t *testing.T) (*server.Server, *httptest.Server, config.Config, string) {
	t.Helper()
	cfg := config.Config{Addr: "127.0.0.1:8787", DataDir: t.TempDir(), AIProvider: "agentrouter", AIBackend: "worker", AIModel: "gpt-6.1-sol", AIBaseURL: "https://agentrouter.org/v1", PublicAccess: true, AccessToken: "private-owner-token", WorkerToken: "private-worker-token", AIKey: "private-model-key"}
	app, err := server.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	host := httptest.NewServer(app.Handler())
	t.Cleanup(func() { host.Close(); app.Store.Close() })
	record := domain.Event{ID: "EVT-worker-fixture", Timestamp: time.Now().UTC(), Kind: "process", Actor: "review-user", Host: "review-host", Source: "owned-lab", Label: "malicious", Raw: "DO_NOT_SEND_RAW", Data: map[string]string{"command": "powershell.exe -EncodedCommand controlled-marker", "password": "DO_NOT_SEND_PASSWORD", "truth_label": "DO_NOT_SEND_TRUTH"}}
	if _, err := app.Store.Import(context.Background(), domain.Dataset{ID: "worker-fixture", Source: "owned-lab", Name: "Worker fixture"}, []domain.Event{record}); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(host.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var state struct {
		Incidents []domain.Incident `json:"incidents"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil || len(state.Incidents) != 1 {
		t.Fatalf("fixture did not create an incident: %#v %v", state, err)
	}
	return app, host, cfg, state.Incidents[0].ID
}

func TestPublicWorkspaceRequiresSeparateWorkerAuthentication(t *testing.T) {
	_, host, cfg, id := queuedWorkspace(t)
	for _, path := range []string{"/api/ai/worker/heartbeat", "/api/ai/worker/claim", "/api/ai/worker/jobs/fake/complete"} {
		resp, err := http.Post(host.URL+path, "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("public visitor could access %s: HTTP %d", path, resp.StatusCode)
		}
	}
	resp, err := http.Post(host.URL+"/api/incidents/"+id+"/report", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatal("offline worker started a report that could not be served")
	}
	resp, err = http.Get(host.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if bytes.Contains(raw, []byte(cfg.WorkerToken)) || bytes.Contains(raw, []byte(cfg.AIKey)) {
		t.Fatal("worker or model credential was exposed to the public workspace")
	}
}

func TestWorkerReportFlowUsesRedactedEvidenceAndValidatedCitations(t *testing.T) {
	app, host, cfg, id := queuedWorkspace(t)
	w, err := worker.New(cfg, host.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := w.Heartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	w.Generate = func(_ context.Context, task domain.ReportTask) (domain.Report, error) {
		for _, sentinel := range []string{"DO_NOT_SEND_RAW", "DO_NOT_SEND_PASSWORD", "DO_NOT_SEND_TRUTH", `"label":`} {
			if strings.Contains(task.Request.Input, sentinel) {
				t.Errorf("private evidence leaked into the worker model request: %s", sentinel)
			}
		}
		return domain.Report{Summary: "Encoded PowerShell was observed.", Verdict: "suspicious", Claims: []domain.Claim{{Text: "The recorded command uses encoded PowerShell.", EvidenceIDs: []string{"EVT-worker-fixture"}}}, NextSteps: []string{"Review the operator's approved change."}, Limitations: []string{"Intent is not established by this event."}}, nil
	}
	resp, err := http.Post(host.URL+"/api/incidents/"+id+"/report", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	var queued struct {
		Job domain.ReportJob `json:"job"`
	}
	json.NewDecoder(resp.Body).Decode(&queued)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted || queued.Job.Status != "queued" {
		t.Fatal("Generate did not enqueue an asynchronous report")
	}
	worked, err := w.WorkOnce(ctx)
	if !worked || err != nil {
		t.Fatalf("worker did not finish a report: %t %v", worked, err)
	}
	report, err := app.Store.Report(ctx, id)
	if err != nil || report.Provider != cfg.AIProvider || report.Model != cfg.AIModel || report.GeneratedAt.IsZero() || report.EvidenceHash != queued.Job.EvidenceHash {
		t.Fatalf("report provenance was not saved correctly: %#v %v", report, err)
	}
	resp, err = http.Get(host.URL + "/api/report-jobs/" + queued.Job.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.Contains(raw, []byte(`"succeeded"`)) || !bytes.Contains(raw, []byte(report.Summary)) || bytes.Contains(raw, []byte(`"claim_token"`)) {
		t.Fatalf("public job poll did not return a safe completed report: %s", raw)
	}
	resp, _ = http.Post(host.URL+"/api/incidents/"+id+"/report", "application/json", strings.NewReader(`{}`))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatal("a validated report was queued again instead of reused")
	}
}

func TestWorkerCannotPublishInventedCitationsOrChangedEvidence(t *testing.T) {
	for _, scenario := range []string{"invented-citation", "changed-evidence"} {
		t.Run(scenario, func(t *testing.T) {
			app, host, cfg, id := queuedWorkspace(t)
			w, err := worker.New(cfg, host.URL)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if err := w.Heartbeat(ctx); err != nil {
				t.Fatal(err)
			}
			resp, _ := http.Post(host.URL+"/api/incidents/"+id+"/report", "application/json", strings.NewReader(`{}`))
			resp.Body.Close()
			w.Generate = func(_ context.Context, task domain.ReportTask) (domain.Report, error) {
				citation := "invented-event"
				if scenario == "changed-evidence" {
					citation = "EVT-worker-fixture"
					// The API review updates evidence and invalidates the local cache.
					request, _ := http.NewRequest(http.MethodPost, host.URL+"/api/events/"+citation+"/label", strings.NewReader(`{"label":"benign","reviewer":"reviewer","reason":"Independent review"}`))
					request.Header.Set("Content-Type", "application/json")
					request.Header.Set("Authorization", "Bearer "+cfg.AccessToken)
					response, err := http.DefaultClient.Do(request)
					if err != nil {
						t.Fatal(err)
					}
					response.Body.Close()
					if response.StatusCode != http.StatusOK {
						t.Fatal("the evidence review failed")
					}
				}
				return domain.Report{Summary: "Observed activity", Verdict: "suspicious", Claims: []domain.Claim{{Text: "Claim", EvidenceIDs: []string{citation}}}, NextSteps: []string{"Review"}, Limitations: []string{"Limited context"}}, nil
			}
			worked, err := w.WorkOnce(ctx)
			if !worked || err == nil {
				t.Fatal("invalid worker report was not rejected")
			}
			if _, err := app.Store.Report(ctx, id); err == nil {
				t.Fatal("a rejected worker report was saved")
			}
		})
	}
}

func TestWorkerFailureDoesNotExposeEitherCredential(t *testing.T) {
	_, host, cfg, id := queuedWorkspace(t)
	w, err := worker.New(cfg, host.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := w.Heartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	resp, _ := http.Post(host.URL+"/api/incidents/"+id+"/report", "application/json", strings.NewReader(`{}`))
	var queued struct {
		Job domain.ReportJob `json:"job"`
	}
	json.NewDecoder(resp.Body).Decode(&queued)
	resp.Body.Close()
	w.Generate = func(context.Context, domain.ReportTask) (domain.Report, error) {
		return domain.Report{}, fmt.Errorf("failure using %s and %s", cfg.AIKey, cfg.WorkerToken)
	}
	_, err = w.WorkOnce(ctx)
	if err == nil || strings.Contains(err.Error(), cfg.WorkerToken) || strings.Contains(err.Error(), cfg.AIKey) {
		t.Fatal("worker failure exposed a credential")
	}
	resp, err = http.Get(host.URL + "/api/report-jobs/" + queued.Job.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Contains(raw, []byte(`"failed"`)) || bytes.Contains(raw, []byte(cfg.AIKey)) || bytes.Contains(raw, []byte(cfg.WorkerToken)) {
		t.Fatal("failed public job leaked a credential or remained pending")
	}
}
