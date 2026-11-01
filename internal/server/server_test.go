package server_test

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/YeandAmen/identityshield/internal/config"
	"github.com/YeandAmen/identityshield/internal/server"
)

func application(t *testing.T, token string) (*server.Server, *httptest.Server) {
	t.Helper()
	app, err := server.New(config.Config{Addr: "127.0.0.1:8787", DataDir: t.TempDir(), Demo: false, AIProvider: "local", AIModel: "evidence-template-v1", AIBaseURL: "https://agentrouter.org/v1", AccessToken: token})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(app.Handler())
	t.Cleanup(func() { httpServer.Close(); app.Store.Close() })
	return app, httpServer
}

func TestCrossOriginAndBearerControls(t *testing.T) {
	_, app := application(t, "workspace-test-token")
	request, _ := http.NewRequest(http.MethodGet, app.URL+"/api/state", nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatal("protected workspace was accessible without its token")
	}
	request, _ = http.NewRequest(http.MethodPost, app.URL+"/api/rules/IS-001", bytes.NewBufferString(`{"enabled":false}`))
	request.Header.Set("Authorization", "Bearer workspace-test-token")
	request.Header.Set("Origin", "https://unrelated.example")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("cross-origin mutation was accepted")
	}
	request, _ = http.NewRequest(http.MethodPost, app.URL+"/api/rules/IS-001", bytes.NewBufferString(`{}`))
	request.Header.Set("Authorization", "Bearer workspace-test-token")
	response, _ = http.DefaultClient.Do(request)
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatal("omitted enabled flag silently changed a rule")
	}
}

func TestImportDetectAndPersistEvidenceBrief(t *testing.T) {
	_, app := application(t, "")
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	file, _ := writer.CreateFormFile("file", "events.jsonl")
	file.Write([]byte(`{"timestamp":"` + time.Now().UTC().Format(time.RFC3339) + `","kind":"process","actor":"user","host":"host","label":"unknown","data":{"command":"powershell.exe -EncodedCommand test-marker"}}`))
	writer.WriteField("format", "canonical")
	writer.WriteField("source", "owned-lab")
	writer.Close()
	response, err := http.Post(app.URL+"/api/datasets/import", writer.FormDataContentType(), &body)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("import status %d", response.StatusCode)
	}
	response, _ = http.Get(app.URL + "/api/state")
	var state struct {
		Incidents []struct {
			ID string `json:"id"`
		} `json:"incidents"`
	}
	json.NewDecoder(response.Body).Decode(&state)
	response.Body.Close()
	if len(state.Incidents) != 1 {
		t.Fatalf("real pipeline did not create a case: %#v", state)
	}
	response, _ = http.Post(app.URL+"/api/incidents/"+state.Incidents[0].ID+"/report", "application/json", bytes.NewBufferString(`{"provider":"local"}`))
	raw, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !bytes.Contains(raw, []byte(`"provider":"local"`)) {
		t.Fatalf("local report was not persisted: %s", raw)
	}
	response, _ = http.Get(app.URL + "/api/export/report/" + state.Incidents[0].ID)
	raw, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !bytes.Contains(raw, []byte("Evidence digest:")) {
		t.Fatal("saved evidence report could not be exported")
	}
}
