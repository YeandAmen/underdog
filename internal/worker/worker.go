package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/YeandAmen/underdog/internal/analyst"
	"github.com/YeandAmen/underdog/internal/config"
	"github.com/YeandAmen/underdog/internal/domain"
	"github.com/YeandAmen/underdog/internal/opencodecli"
)

type Worker struct {
	Config   config.Config
	URL      string
	HTTP     *http.Client
	Generate func(context.Context, domain.ReportTask) (domain.Report, error)
}

func New(c config.Config, workspaceURL string) (*Worker, error) {
	u, err := url.Parse(workspaceURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("worker workspace URL must be an absolute HTTPS URL without credentials or a path")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback())) {
		return nil, errors.New("worker workspace requires HTTPS, except for a loopback development server")
	}
	if c.WorkerToken == "" {
		return nil, errors.New("set UNDERDOG_WORKER_TOKEN in the ignored .env to connect the report worker")
	}
	w := &Worker{Config: c, URL: strings.TrimRight(workspaceURL, "/"), HTTP: &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("use the canonical workspace URL for the report worker")
		},
	}}
	w.Generate = func(ctx context.Context, task domain.ReportTask) (domain.Report, error) {
		if c.AIProvider != "ollama" && c.AIKey == "" {
			return domain.Report{}, errors.New("the report worker's model credential is not configured")
		}
		text, err := opencodecli.Complete(ctx, c, task.Request.System, task.Request.Input, task.Request.Schema)
		if err != nil {
			return domain.Report{}, err
		}
		return analyst.ParseReport(text)
	}
	return w, nil
}

func (w *Worker) request(ctx context.Context, path string, payload any) ([]byte, int, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL+path, bytes.NewReader(data))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+w.Config.WorkerToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := w.HTTP.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("could not reach the report workspace: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	if err != nil || len(raw) > 2<<20 {
		return nil, resp.StatusCode, errors.New("the report workspace response could not be read")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var problem struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &problem) != nil || problem.Error == "" {
			return nil, resp.StatusCode, fmt.Errorf("report workspace returned HTTP %d", resp.StatusCode)
		}
		return nil, resp.StatusCode, errors.New(w.redact(problem.Error))
	}
	return raw, resp.StatusCode, nil
}

func (w *Worker) identity() map[string]string {
	return map[string]string{"provider": w.Config.AIProvider, "model": w.Config.AIModel}
}

func (w *Worker) Heartbeat(ctx context.Context) error {
	_, _, err := w.request(ctx, "/api/ai/worker/heartbeat", w.identity())
	return err
}

func (w *Worker) finish(ctx context.Context, task domain.ReportTask, report *domain.Report, generationError error) error {
	payload := map[string]any{"claim_token": task.ClaimToken}
	if generationError != nil {
		payload["error"] = w.redact(generationError.Error())
	} else {
		payload["report"] = report
	}
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		_, status, err := w.request(ctx, "/api/ai/worker/jobs/"+url.PathEscape(task.Job.ID)+"/complete", payload)
		if err == nil {
			return nil
		}
		last = err
		if status >= 400 && status < 500 || ctx.Err() != nil {
			break
		}
		if !wait(ctx, time.Duration(attempt+1)*time.Second) {
			break
		}
	}
	return last
}

func (w *Worker) WorkOnce(ctx context.Context) (bool, error) {
	raw, status, err := w.request(ctx, "/api/ai/worker/claim", w.identity())
	if err != nil || status == http.StatusNoContent {
		return false, err
	}
	var task domain.ReportTask
	if err := json.Unmarshal(raw, &task); err != nil || task.Job.ID == "" || task.ClaimToken == "" || task.Request.Input == "" || task.Request.Schema == nil {
		return false, errors.New("the workspace returned an invalid report task")
	}
	if task.Job.Provider != w.Config.AIProvider || task.Job.Model != w.Config.AIModel {
		return false, errors.New("the report task does not match the worker's configured model")
	}
	slog.Info("Reading incident evidence with OpenCode", "incident", task.Job.IncidentID, "model", "Our model")
	started := time.Now()
	generation, cancel := context.WithTimeout(ctx, 6*time.Minute)
	report, generationError := w.Generate(generation, task)
	cancel()
	// Release a claimed job even when the terminal is closing. Lease expiry is
	// the recovery path if the workspace cannot be reached during shutdown.
	completion, stop := context.WithTimeout(context.WithoutCancel(ctx), 65*time.Second)
	defer stop()
	if err := w.finish(completion, task, &report, generationError); err != nil {
		return true, err
	}
	if generationError != nil {
		return true, errors.New(w.redact(generationError.Error()))
	}
	slog.Info("Validated report published", "incident", task.Job.IncidentID, "claims", len(report.Claims), "seconds", int(time.Since(started).Seconds()))
	return true, nil
}

func (w *Worker) Run(ctx context.Context, interval time.Duration, once bool) error {
	if interval < time.Second || interval > 30*time.Second {
		return errors.New("worker poll interval must be between 1s and 30s")
	}
	if err := w.Heartbeat(ctx); err != nil {
		return err
	}
	slog.Info("Underdog report worker connected", "workspace", w.URL, "engine", "OpenCode", "model", "Our model")
	heartbeat, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeat.Done():
				return
			case <-ticker.C:
				if err := w.Heartbeat(heartbeat); err != nil && heartbeat.Err() == nil {
					slog.Warn("Report worker heartbeat failed", "error", err)
				}
			}
		}
	}()
	for ctx.Err() == nil {
		worked, err := w.WorkOnce(ctx)
		if once {
			if !worked && err == nil {
				slog.Info("No report jobs are queued")
			}
			return err
		}
		if err != nil && ctx.Err() == nil {
			slog.Warn("Report job could not be completed", "error", err)
		}
		if !worked || err != nil {
			if !wait(ctx, interval) {
				break
			}
		}
	}
	return nil
}

func wait(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (w *Worker) redact(message string) string {
	for _, secret := range []string{w.Config.WorkerToken, w.Config.AIKey} {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[redacted]")
		}
	}
	if w.Config.AIModel != "" {
		message = strings.ReplaceAll(message, w.Config.AIModel, "our model")
	}
	return message[:min(1000, len(message))]
}
