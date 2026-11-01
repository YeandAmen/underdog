package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/YeandAmen/identityshield/internal/analyst"
	"github.com/YeandAmen/identityshield/internal/config"
	"github.com/YeandAmen/identityshield/internal/datasets"
	"github.com/YeandAmen/identityshield/internal/detection"
	"github.com/YeandAmen/identityshield/internal/domain"
	"github.com/YeandAmen/identityshield/internal/identity"
	"github.com/YeandAmen/identityshield/internal/lab"
	"github.com/YeandAmen/identityshield/internal/research"
	"github.com/YeandAmen/identityshield/internal/store"
	"github.com/YeandAmen/identityshield/web"
)

type Server struct {
	Config   config.Config
	Store    *store.Store
	Analyst  *analyst.Client
	mutation sync.Mutex
	training sync.Mutex
	changes  chan struct{}
	cacheMu  sync.Mutex
	revision atomic.Uint64
	cache    *workspaceCache
}

type workspaceCache struct {
	revision  uint64
	events    []domain.Event
	snapshot  domain.Snapshot
	incidents []domain.Incident
}

func New(c config.Config) (*Server, error) {
	db, err := store.Open(c.DataDir)
	if err != nil {
		return nil, err
	}
	s := &Server{Config: c, Store: db, Analyst: analyst.New(c), changes: make(chan struct{}, 1)}
	if err := s.initialize(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Server) initialize() error {
	ctx := context.Background()
	var snapshot domain.Snapshot
	err := s.Store.Get(ctx, "snapshot", &snapshot)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if errors.Is(err, sql.ErrNoRows) {
		if s.Config.Demo {
			snapshot = lab.Snapshot(time.Now())
		} else {
			snapshot = domain.Snapshot{ID: "empty-workspace", Organization: "Your organization", PolicyVersion: "unconfigured", CapturedAt: time.Now().UTC(), Source: "unconfigured", Users: []domain.User{}, Groups: []domain.Group{}, Assets: []domain.Asset{}, Grants: []domain.Grant{}, Policies: []domain.Policy{}}
		}
		if err := s.Store.Put(ctx, "snapshot", snapshot); err != nil {
			return err
		}
	}
	var initialized bool
	if err := s.Store.Get(ctx, "demo_initialized", &initialized); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if s.Config.Demo && !initialized {
		existing, err := s.Store.Datasets(ctx)
		if err != nil {
			return err
		}
		found := false
		for _, dataset := range existing {
			found = found || dataset.ID == "northstar-lab"
		}
		if !found {
			events := lab.Baseline(time.Now())
			data, _ := json.Marshal(events)
			hash := sha256.Sum256(data)
			_, err := s.Store.Import(ctx, domain.Dataset{ID: "northstar-lab", Name: "Northstar · controlled lab", Source: "synthetic-lab", Format: "canonical", ImportedAt: time.Now().UTC(), SHA256: fmt.Sprintf("%x", hash), License: "Project-owned synthetic fixtures", Synthetic: true, Notes: "Reproducible synthetic authentication and tank-process runs. Labels come from controlled scenario generation, not model predictions. No Windows VM or physical plant is connected by these fixtures."}, events)
			if err != nil {
				return err
			}
		}
		if err := s.Store.Put(ctx, "demo_initialized", true); err != nil {
			return err
		}
	}
	if s.Config.Demo {
		events, err := s.Store.Events(ctx, 200000)
		if err != nil {
			return err
		}
		for _, kind := range []string{"authentication", "ics"} {
			var model research.Model
			err := s.Store.Get(ctx, "model/"+kind, &model)
			if errors.Is(err, sql.ErrNoRows) {
				model, trainErr := research.Train(events, kind, "northstar-lab")
				if trainErr != nil {
					return trainErr
				}
				if err := s.Store.Put(ctx, "model/"+kind, model); err != nil {
					return err
				}
			} else if err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/state", s.state)
	mux.HandleFunc("GET /api/incidents/{id}", s.incident)
	mux.HandleFunc("POST /api/incidents/{id}/report", s.report)
	mux.HandleFunc("POST /api/incidents/{id}/review", s.review)
	mux.HandleFunc("POST /api/events/{id}/label", s.label)
	mux.HandleFunc("GET /api/events", s.events)
	mux.HandleFunc("GET /api/stream", s.stream)
	mux.HandleFunc("POST /api/identity/snapshot", s.snapshot)
	mux.HandleFunc("POST /api/identity/preview", s.preview)
	mux.HandleFunc("POST /api/lab/replay", s.replay)
	mux.HandleFunc("POST /api/rules/{id}", s.rule)
	mux.HandleFunc("POST /api/datasets/import", s.importDataset)
	mux.HandleFunc("POST /api/datasets/reprocess/{id}", s.reprocess)
	mux.HandleFunc("POST /api/datasets/fetch/{id}", s.fetchDataset)
	mux.HandleFunc("POST /api/datasets/kaggle", s.kaggle)
	mux.HandleFunc("GET /api/datasets/kaggle/files", s.kaggleFiles)
	mux.HandleFunc("POST /api/research/train", s.train)
	mux.HandleFunc("POST /api/ai/check", s.checkAI)
	mux.HandleFunc("GET /api/export/events", s.exportEvents)
	mux.HandleFunc("GET /api/export/report/{id}", s.exportReport)
	mux.HandleFunc("GET /api/export/model/{domain}", s.exportModel)
	assets, _ := fs.Sub(web.Files, "assets")
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(assets))))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		allowed := map[string]bool{"/": true, "/investigations": true, "/identity": true, "/datasets": true, "/research": true, "/rules": true}
		if !allowed[r.URL.Path] {
			http.NotFound(w, r)
			return
		}
		body, _ := web.Files.ReadFile("index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(body)
	})
	return s.middleware(mux)
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
			if r.URL.Path != "/api/health" && s.Config.AccessToken != "" {
				token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
				if subtle.ConstantTimeCompare([]byte(token), []byte(s.Config.AccessToken)) != 1 {
					problem(w, http.StatusUnauthorized, "Workspace access token required")
					return
				}
			}
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				if origin := r.Header.Get("Origin"); origin != "" {
					u, err := url.Parse(origin)
					if err != nil || !strings.EqualFold(u.Host, r.Host) {
						problem(w, http.StatusForbidden, "Cross-origin mutations are not permitted")
						return
					}
				} else if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
					problem(w, http.StatusForbidden, "Cross-site mutations are not permitted")
					return
				}
			}
		}
		defer func() {
			if err := recover(); err != nil {
				slog.Error("request failed", "path", r.URL.Path)
				problem(w, http.StatusInternalServerError, "The request could not be completed")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		slog.Debug("response disconnected")
	}
}

func problem(w http.ResponseWriter, status int, message string) {
	respond(w, status, map[string]string{"error": message})
}

func decode(w http.ResponseWriter, r *http.Request, out any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		problem(w, http.StatusBadRequest, "Invalid JSON request: "+err.Error())
		return false
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		problem(w, http.StatusBadRequest, "Request must contain one JSON value")
		return false
	}
	return true
}

func (s *Server) load(ctx context.Context) ([]domain.Event, domain.Snapshot, []domain.Incident, error) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	revision := s.revision.Load()
	if s.cache != nil && s.cache.revision == revision {
		return s.cache.events, s.cache.snapshot, s.cache.incidents, nil
	}
	events, snapshot, incidents, err := s.loadFresh(ctx)
	if err == nil && revision == s.revision.Load() {
		s.cache = &workspaceCache{revision: revision, events: events, snapshot: snapshot, incidents: incidents}
	}
	return events, snapshot, incidents, err
}

func (s *Server) loadFresh(ctx context.Context) ([]domain.Event, domain.Snapshot, []domain.Incident, error) {
	events, err := s.Store.Events(ctx, 200000)
	if err != nil {
		return nil, domain.Snapshot{}, nil, err
	}
	var snapshot domain.Snapshot
	if err := s.Store.Get(ctx, "snapshot", &snapshot); err != nil {
		return nil, snapshot, nil, err
	}
	enabled := map[string]bool{}
	if err := s.Store.Get(ctx, "rules", &enabled); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, snapshot, nil, err
	}
	incidents := detection.Detect(events, snapshot, enabled, true)
	for _, kind := range []string{"authentication", "ics"} {
		var model research.Model
		if err := s.Store.Get(ctx, "model/"+kind, &model); err == nil {
			incidents = append(incidents, research.Infer(model, events, snapshot)...)
		} else if !errors.Is(err, sql.ErrNoRows) {
			return nil, snapshot, nil, err
		}
	}
	research.Rank(incidents)
	reviews, err := s.Store.Reviews(ctx)
	if err != nil {
		return nil, snapshot, nil, err
	}
	for i := range incidents {
		if review, exists := reviews[incidents[i].ID]; exists {
			switch review.Verdict {
			case "benign":
				incidents[i].Status = "closed"
			case "malicious":
				incidents[i].Status = "confirmed"
			}
		}
	}
	return events, snapshot, incidents, nil
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	respond(w, http.StatusOK, map[string]any{"status": "ok", "name": "IdentityShield", "version": "0.1.0", "requires_token": s.Config.AccessToken != ""})
}

func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	events, snapshot, incidents, err := s.load(r.Context())
	if err != nil {
		problem(w, http.StatusInternalServerError, "Could not load workspace")
		return
	}
	imports, err := s.Store.Datasets(r.Context())
	if err != nil {
		problem(w, http.StatusInternalServerError, "Could not load dataset provenance")
		return
	}
	reviews, err := s.Store.Reviews(r.Context())
	if err != nil {
		problem(w, http.StatusInternalServerError, "Could not load analyst reviews")
		return
	}
	models := map[string]research.Model{}
	for _, kind := range []string{"authentication", "ics"} {
		var model research.Model
		err := s.Store.Get(r.Context(), "model/"+kind, &model)
		if err == nil {
			model.Trees = nil
			models[kind] = model
		} else if !errors.Is(err, sql.ErrNoRows) {
			problem(w, http.StatusInternalServerError, "Could not load model")
			return
		}
	}
	rules := detection.Rules()
	enabled := map[string]bool{}
	if err := s.Store.Get(r.Context(), "rules", &enabled); err != nil && !errors.Is(err, sql.ErrNoRows) {
		problem(w, http.StatusInternalServerError, "Could not load rule configuration")
		return
	}
	for i := range rules {
		if active, exists := enabled[rules[i].ID]; exists {
			rules[i].Enabled = active
		}
		for _, incident := range incidents {
			if incident.RuleID == rules[i].ID {
				rules[i].Matches++
			}
		}
	}
	findings := identity.Audit(snapshot)
	now := time.Now().UTC()
	counts := map[string]int{"events": len(events), "identities": len(snapshot.Users), "findings": len(findings), "open_incidents": 0, "critical_findings": 0, "benign": 0, "malicious": 0, "unknown": 0, "active_rules": 0, "matched_rules": 0, "synthetic_events": 0}
	for _, event := range events {
		counts[event.Label]++
		if event.Source == "synthetic-lab" {
			counts["synthetic_events"]++
		}
	}
	for _, finding := range findings {
		if finding.Severity == "critical" {
			counts["critical_findings"]++
		}
	}
	for _, incident := range incidents {
		if incident.Status == "open" {
			counts["open_incidents"]++
		}
	}
	for _, rule := range rules {
		if rule.Enabled {
			counts["active_rules"]++
		}
		if rule.Matches > 0 {
			counts["matched_rules"]++
		}
	}
	type point struct {
		Time   time.Time `json:"time"`
		Events int       `json:"events"`
		Alerts int       `json:"alerts"`
	}
	series := make([]point, 48)
	start := now.Truncate(30 * time.Minute).Add(-47 * 30 * time.Minute)
	for i := range series {
		series[i].Time = start.Add(time.Duration(i) * 30 * time.Minute)
	}
	for _, event := range events {
		i := int(event.Timestamp.Sub(start) / (30 * time.Minute))
		if !event.Timestamp.Before(start) && i >= 0 && i < len(series) {
			series[i].Events++
		}
	}
	for _, incident := range incidents {
		i := int(incident.StartedAt.Sub(start) / (30 * time.Minute))
		if !incident.StartedAt.Before(start) && i >= 0 && i < len(series) {
			series[i].Alerts++
		}
	}
	dataMode := "empty"
	if len(events) > 0 {
		dataMode = "imported"
		if counts["synthetic_events"] == len(events) {
			dataMode = "synthetic"
		} else if counts["synthetic_events"] > 0 {
			dataMode = "mixed"
		}
	}
	base, _ := url.Parse(s.Config.AIBaseURL)
	respond(w, http.StatusOK, map[string]any{
		"organization": snapshot.Organization, "snapshot": snapshot, "findings": findings,
		"incidents": incidents, "rules": rules, "datasets": imports, "catalog": datasets.Catalog(),
		"models": models, "counts": counts, "series": series, "reviews": reviews,
		"data_mode": dataMode, "now": now, "analysis_window_limit": 200000,
		"ai":                map[string]any{"provider": s.Config.AIProvider, "model": s.Config.AIModel, "configured": s.Config.AIKey != "" || s.Config.AIProvider == "local" || s.Config.AIProvider == "ollama", "remote": s.Config.AIProvider == "agentrouter" || s.Config.AIProvider == "openrouter", "host": base.Host},
		"kaggle_configured": s.Config.KaggleToken != "" || (s.Config.KaggleUsername != "" && s.Config.KaggleKey != ""),
		"scenarios":         lab.ScenarioNames(),
	})
}

func bundle(events []domain.Event, snapshot domain.Snapshot, incident domain.Incident) (domain.Incident, []domain.Event) {
	matching := map[string]bool{}
	var runID, source string
	for _, id := range incident.EventIDs {
		matching[id] = true
	}
	for _, event := range events {
		if matching[event.ID] {
			runID, source = event.RunID, event.Source
			break
		}
	}
	selected := []domain.Event{}
	for _, event := range events {
		related := runID != "" && event.RunID == runID && event.Source == source && !event.Timestamp.Before(incident.StartedAt.Add(-5*time.Minute)) && !event.Timestamp.After(incident.LastSeen.Add(5*time.Minute))
		if matching[event.ID] || related {
			selected = append(selected, event)
		}
	}
	if len(selected) > 120 {
		// Matching evidence is selected first when bounding the model context.
		bounded := []domain.Event{}
		for _, event := range selected {
			if matching[event.ID] && len(bounded) < 120 {
				bounded = append(bounded, event)
			}
		}
		for _, event := range selected {
			if !matching[event.ID] && len(bounded) < 120 {
				bounded = append(bounded, event)
			}
		}
		selected = bounded
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Timestamp.Before(selected[j].Timestamp) })
	digest, _ := json.Marshal([]any{selected, snapshot, incident.Context, incident.RuleID})
	hash := sha256.Sum256(digest)
	incident.EvidenceHash = fmt.Sprintf("%x", hash)
	return incident, selected
}

func (s *Server) investigation(ctx context.Context, id string) (domain.Incident, []domain.Event, error) {
	events, snapshot, incidents, err := s.load(ctx)
	if err != nil {
		return domain.Incident{}, nil, err
	}
	for _, incident := range incidents {
		if incident.ID == id {
			incident, selected := bundle(events, snapshot, incident)
			return incident, selected, nil
		}
	}
	return domain.Incident{}, nil, sql.ErrNoRows
}

func (s *Server) incident(w http.ResponseWriter, r *http.Request) {
	incident, events, err := s.investigation(r.Context(), r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusNotFound, "Investigation not found")
		return
	}
	var report *domain.Report
	if existing, err := s.Store.Report(r.Context(), incident.ID); err == nil && existing.EvidenceHash == incident.EvidenceHash {
		report = &existing
	}
	respond(w, http.StatusOK, map[string]any{"incident": incident, "events": events, "brief": analyst.Template(incident, events), "report": report})
}

func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Provider string `json:"provider"`
	}
	if !decode(w, r, &input) {
		return
	}
	incident, events, err := s.investigation(r.Context(), r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusNotFound, "Investigation not found")
		return
	}
	client := s.Analyst
	if input.Provider == "local" {
		cfg := s.Config
		cfg.AIProvider = "local"
		client = analyst.New(cfg)
	} else if input.Provider != "" && input.Provider != s.Config.AIProvider {
		problem(w, http.StatusBadRequest, "Requested provider is not configured")
		return
	}
	report, err := client.Report(r.Context(), incident, events)
	if err != nil {
		problem(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := s.Store.PutReport(r.Context(), report); err != nil {
		problem(w, http.StatusInternalServerError, "Could not save report")
		return
	}
	respond(w, http.StatusOK, report)
}

func (s *Server) review(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Verdict  string `json:"verdict"`
		Reason   string `json:"reason"`
		Reviewer string `json:"reviewer"`
	}
	if !decode(w, r, &input) {
		return
	}
	if !domain.ValidLabel(input.Verdict) || strings.TrimSpace(input.Reason) == "" || len(input.Reason) > 4000 || strings.TrimSpace(input.Reviewer) == "" {
		problem(w, http.StatusBadRequest, "A valid verdict, reviewer, and explanation are required")
		return
	}
	if _, _, err := s.investigation(r.Context(), r.PathValue("id")); err != nil {
		problem(w, http.StatusNotFound, "Investigation not found")
		return
	}
	review := domain.Review{IncidentID: r.PathValue("id"), Verdict: input.Verdict, Reason: input.Reason, Reviewer: input.Reviewer, ReviewedAt: time.Now().UTC()}
	if err := s.Store.PutReview(r.Context(), review); err != nil {
		problem(w, http.StatusInternalServerError, "Could not save review")
		return
	}
	s.changed()
	respond(w, http.StatusOK, review)
}

func (s *Server) label(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Label    string `json:"label"`
		Reviewer string `json:"reviewer"`
		Reason   string `json:"reason"`
	}
	if !decode(w, r, &input) {
		return
	}
	if !domain.ValidLabel(input.Label) || strings.TrimSpace(input.Reviewer) == "" || strings.TrimSpace(input.Reason) == "" || len(input.Reason) > 4000 {
		problem(w, http.StatusBadRequest, "Label, reviewer, and review reason are required")
		return
	}
	if err := s.Store.LabelEvent(r.Context(), r.PathValue("id"), input.Label, input.Reviewer, input.Reason); err != nil {
		problem(w, http.StatusBadRequest, "Could not label the event; check the event ID and review fields")
		return
	}
	s.changed()
	respond(w, http.StatusOK, map[string]bool{"saved": true})
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	events, _, _, err := s.load(r.Context())
	if err != nil {
		problem(w, http.StatusInternalServerError, "Could not read evidence")
		return
	}
	query := strings.ToLower(r.URL.Query().Get("q"))
	label, source := r.URL.Query().Get("label"), r.URL.Query().Get("source")
	out := []domain.Event{}
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if label != "" && event.Label != label || source != "" && event.Source != source {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(event.Actor+" "+event.Host+" "+event.Kind+" "+event.ID), query) {
			continue
		}
		out = append(out, event)
	}
	total := len(out)
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	start := min((page-1)*50, len(out))
	out = out[start:min(start+50, len(out))]
	respond(w, http.StatusOK, map[string]any{"events": out, "total": total, "page": page, "page_size": 50})
}

func (s *Server) snapshot(w http.ResponseWriter, r *http.Request) {
	var snapshot domain.Snapshot
	if !decode(w, r, &snapshot) {
		return
	}
	if err := identity.Validate(snapshot); err != nil {
		problem(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mutation.Lock()
	defer s.mutation.Unlock()
	if err := s.Store.Put(r.Context(), "snapshot", snapshot); err != nil {
		problem(w, http.StatusInternalServerError, "Could not save snapshot")
		return
	}
	s.changed()
	respond(w, http.StatusOK, map[string]any{"saved": true, "findings": identity.Audit(snapshot)})
}

func (s *Server) preview(w http.ResponseWriter, r *http.Request) {
	var input struct {
		FindingID string `json:"finding_id"`
	}
	if !decode(w, r, &input) {
		return
	}
	var snapshot domain.Snapshot
	if err := s.Store.Get(r.Context(), "snapshot", &snapshot); err != nil {
		problem(w, http.StatusInternalServerError, "Could not load snapshot")
		return
	}
	before := identity.Audit(snapshot)
	for _, finding := range before {
		if finding.ID != input.FindingID {
			continue
		}
		// A preview explicitly shows the blast radius of removing this grant.
		// It never writes to AD or silently changes the stored snapshot.
		grants := []domain.Grant{}
		for _, grant := range snapshot.Grants {
			if grant.ID != finding.GrantID {
				grants = append(grants, grant)
			}
		}
		preview := snapshot
		preview.Grants = grants
		affected := []string{}
		for _, user := range snapshot.Users {
			paths := identity.MembershipPaths(snapshot, user)
			for _, grant := range snapshot.Grants {
				if grant.ID == finding.GrantID && paths[grant.Principal] != nil {
					affected = append(affected, user.Name)
				}
			}
		}
		respond(w, http.StatusOK, map[string]any{"finding": finding, "before": before, "after": identity.Audit(preview), "affected_users": affected, "removed_grant": finding.GrantID, "recommendation": "Prefer removing the unintended membership edge when the grant also serves legitimate users. This grant-removal preview shows the impact, not an automatically recommended production change.", "mode": "read-only snapshot preview; no AD writes"})
		return
	}
	problem(w, http.StatusNotFound, "Permission finding not found")
}

func (s *Server) replay(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Scenario string `json:"scenario"`
	}
	if !decode(w, r, &input) {
		return
	}
	valid := false
	for _, name := range lab.ScenarioNames() {
		valid = valid || name == input.Scenario
	}
	if !valid {
		problem(w, http.StatusBadRequest, "Unknown lab scenario")
		return
	}
	now := time.Now().UTC()
	runID := fmt.Sprintf("replay-%d", now.UnixNano())
	events := lab.Scenario(input.Scenario, runID, now)
	raw, _ := json.Marshal(events)
	hash := sha256.Sum256(raw)
	dataset := domain.Dataset{ID: runID, Name: "Lab replay · " + strings.ReplaceAll(input.Scenario, "-", " "), Source: "synthetic-lab", Format: "canonical", ImportedAt: now, SHA256: fmt.Sprintf("%x", hash), License: "Project-owned synthetic fixtures", Synthetic: true, Notes: "Controlled telemetry replay. No exploit, VM command, or physical process command is executed."}
	dataset, err := s.Store.Import(r.Context(), dataset, events)
	if err != nil {
		problem(w, http.StatusInternalServerError, "Could not store scenario replay")
		return
	}
	s.changed()
	respond(w, http.StatusCreated, dataset)
}

func (s *Server) rule(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Enabled *bool `json:"enabled"`
	}
	if !decode(w, r, &input) {
		return
	}
	if input.Enabled == nil {
		problem(w, http.StatusBadRequest, "The enabled field is required")
		return
	}
	found := false
	for _, rule := range detection.Rules() {
		found = found || rule.ID == r.PathValue("id")
	}
	if !found {
		problem(w, http.StatusNotFound, "Rule not found")
		return
	}
	s.mutation.Lock()
	defer s.mutation.Unlock()
	rules := map[string]bool{}
	if err := s.Store.Get(r.Context(), "rules", &rules); err != nil && !errors.Is(err, sql.ErrNoRows) {
		problem(w, http.StatusInternalServerError, "Could not load rules")
		return
	}
	rules[r.PathValue("id")] = *input.Enabled
	if err := s.Store.Put(r.Context(), "rules", rules); err != nil {
		problem(w, http.StatusInternalServerError, "Could not save rule")
		return
	}
	s.changed()
	respond(w, http.StatusOK, map[string]bool{"saved": true})
}

func (s *Server) saveImport(ctx context.Context, name, source, format, license, sourceURL string, raw []byte, opts datasets.Options) (domain.Dataset, error) {
	result, err := datasets.Parse(raw, opts)
	if err != nil {
		return domain.Dataset{}, err
	}
	id := "DATA-" + result.SHA256[:16]
	notes := strings.Join(result.Notes, " ")
	if entry, exists := datasets.Entry(source); exists {
		if sourceURL == "" {
			sourceURL = entry.SourceURL
		}
		if license == "" {
			license = entry.License
		}
		notes += " " + entry.Notes
	}
	if license == "" {
		license = "Not specified by importer"
	}
	if opts.VerifiedNormal {
		notes += " Importer explicitly asserted this is verified normal-only data."
	}
	if sourceURL != "" {
		u, err := url.Parse(sourceURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return domain.Dataset{}, errors.New("source URL must be an HTTP(S) publisher URL without credentials")
		}
	}
	dir := filepath.Join(s.Config.DataDir, "imports")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return domain.Dataset{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, result.SHA256+".payload"), raw, 0600); err != nil {
		return domain.Dataset{}, err
	}
	d := domain.Dataset{ID: id, Name: name, Source: source, Format: format, ImportedAt: time.Now().UTC(), SHA256: result.SHA256, SourceURL: sourceURL, License: license, Synthetic: source == "synthetic-lab", Notes: strings.TrimSpace(notes)}
	return s.Store.Import(ctx, d, result.Events)
}

func (s *Server) importDataset(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, datasets.MaxPayloadBytes+4<<20)
	if err := r.ParseMultipartForm(4 << 20); err != nil {
		problem(w, http.StatusBadRequest, "Could not read upload; payload limit is 64 MiB")
		return
	}
	defer r.MultipartForm.RemoveAll()
	file, header, err := r.FormFile("file")
	if err != nil {
		problem(w, http.StatusBadRequest, "Choose an evidence file")
		return
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, datasets.MaxPayloadBytes+1))
	if err != nil || len(raw) > datasets.MaxPayloadBytes {
		problem(w, http.StatusBadRequest, "Evidence payload exceeds 64 MiB")
		return
	}
	source, format := strings.TrimSpace(r.FormValue("source")), r.FormValue("format")
	if source == "" {
		source = "user-import"
	}
	if len(source) > 100 {
		problem(w, http.StatusBadRequest, "Source identifier is too long")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = filepath.Base(header.Filename)
	}
	if len(name) > 200 {
		problem(w, http.StatusBadRequest, "Dataset name is too long")
		return
	}
	opts := datasets.Options{Format: format, Source: source, VerifiedNormal: r.FormValue("verified_normal") == "true"}
	if labelFile, _, err := r.FormFile("labels"); err == nil {
		defer labelFile.Close()
		opts.RedTeam, err = io.ReadAll(io.LimitReader(labelFile, 2<<20+1))
		if err != nil || len(opts.RedTeam) > 2<<20 {
			problem(w, http.StatusBadRequest, "Companion labels exceed 2 MiB")
			return
		}
	}
	dataset, err := s.saveImport(r.Context(), name, source, format, r.FormValue("license"), r.FormValue("source_url"), raw, opts)
	if err != nil {
		problem(w, http.StatusBadRequest, err.Error())
		return
	}
	s.changed()
	respond(w, http.StatusCreated, dataset)
}

func (s *Server) fetchDataset(w http.ResponseWriter, r *http.Request) {
	entry, found := datasets.Entry(r.PathValue("id"))
	if !found || !entry.CanFetch || entry.DownloadURL == "" {
		problem(w, http.StatusBadRequest, "This source requires a publisher download or a normalized export")
		return
	}
	request, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, entry.DownloadURL, nil)
	response, err := (&http.Client{Timeout: 60 * time.Second}).Do(request)
	if err != nil {
		problem(w, http.StatusBadGateway, "Could not reach the dataset publisher")
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		problem(w, http.StatusBadGateway, fmt.Sprintf("Publisher returned HTTP %d", response.StatusCode))
		return
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, datasets.MaxPayloadBytes+1))
	if err != nil || len(raw) > datasets.MaxPayloadBytes {
		problem(w, http.StatusBadGateway, "Publisher payload exceeded the import limit")
		return
	}
	dataset, err := s.saveImport(r.Context(), entry.Name+" · DCSync host capture", entry.ID, entry.Format, entry.License, entry.DownloadURL, raw, datasets.Options{Format: entry.Format, Source: entry.ID})
	if err != nil {
		problem(w, http.StatusBadRequest, err.Error())
		return
	}
	s.changed()
	respond(w, http.StatusCreated, dataset)
}

func (s *Server) reprocess(w http.ResponseWriter, r *http.Request) {
	imports, err := s.Store.Datasets(r.Context())
	if err != nil {
		problem(w, http.StatusInternalServerError, "Could not load manifests")
		return
	}
	for _, dataset := range imports {
		if dataset.ID != r.PathValue("id") || len(dataset.SHA256) != 64 {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(s.Config.DataDir, "imports", dataset.SHA256+".payload"))
		if err != nil {
			problem(w, http.StatusNotFound, "Original import payload is not available")
			return
		}
		result, err := datasets.Parse(raw, datasets.Options{Source: dataset.Source, Format: dataset.Format})
		if err != nil || result.SHA256 != dataset.SHA256 {
			problem(w, http.StatusBadRequest, "Original payload could not be validated with the current normalizer")
			return
		}
		updated, err := s.Store.Reprocess(r.Context(), dataset.ID, result.Events)
		if err != nil {
			problem(w, http.StatusBadRequest, err.Error())
			return
		}
		s.changed()
		respond(w, http.StatusOK, map[string]any{"updated": updated, "labels_preserved": true, "payload_sha256": dataset.SHA256})
		return
	}
	problem(w, http.StatusNotFound, "Dataset manifest not found")
}

func (s *Server) kaggle(w http.ResponseWriter, r *http.Request) {
	var input struct {
		File string `json:"file"`
	}
	if !decode(w, r, &input) {
		return
	}
	if input.File == "" || strings.Contains(input.File, "..") || strings.HasPrefix(input.File, "/") || (!strings.HasSuffix(input.File, ".csv") && !strings.HasSuffix(input.File, ".csv.gz")) {
		problem(w, http.StatusBadRequest, "Specify a HAI CSV filename from the publisher dataset; a bounded single-file download is required")
		return
	}
	endpoint := "https://www.kaggle.com/api/v1/datasets/download/icsdataset/hai-security-dataset?fileName=" + url.QueryEscape(input.File)
	request, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, endpoint, nil)
	if s.Config.KaggleToken != "" {
		request.Header.Set("Authorization", "Bearer "+s.Config.KaggleToken)
	} else if s.Config.KaggleUsername != "" && s.Config.KaggleKey != "" {
		request.SetBasicAuth(s.Config.KaggleUsername, s.Config.KaggleKey)
	}
	response, err := (&http.Client{Timeout: 60 * time.Second}).Do(request)
	if err != nil {
		problem(w, http.StatusBadGateway, "Could not reach Kaggle")
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		problem(w, http.StatusBadGateway, fmt.Sprintf("Kaggle returned HTTP %d; verify credentials and the exact publisher filename", response.StatusCode))
		return
	}
	if strings.Contains(response.Header.Get("Content-Type"), "text/html") {
		problem(w, http.StatusBadGateway, "Kaggle returned a web page instead of a dataset file; verify publisher access and filename")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, datasets.MaxPayloadBytes+1))
	if err != nil || len(raw) > datasets.MaxPayloadBytes {
		problem(w, http.StatusBadGateway, "Kaggle file exceeds the 64 MiB import limit; prepare a bounded local slice")
		return
	}
	entry, _ := datasets.Entry("hai")
	dataset, err := s.saveImport(r.Context(), "HAI · "+input.File, "hai", "hai-csv", entry.License, "https://www.kaggle.com/datasets/icsdataset/hai-security-dataset", raw, datasets.Options{Format: "hai-csv", Source: "hai"})
	if err != nil {
		problem(w, http.StatusBadRequest, err.Error())
		return
	}
	s.changed()
	respond(w, http.StatusCreated, dataset)
}

func (s *Server) kaggleFiles(w http.ResponseWriter, r *http.Request) {
	request, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, "https://www.kaggle.com/api/v1/datasets/list/icsdataset/hai-security-dataset?pageSize=100", nil)
	if s.Config.KaggleToken != "" {
		request.Header.Set("Authorization", "Bearer "+s.Config.KaggleToken)
	} else if s.Config.KaggleUsername != "" && s.Config.KaggleKey != "" {
		request.SetBasicAuth(s.Config.KaggleUsername, s.Config.KaggleKey)
	}
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
	if err != nil {
		problem(w, http.StatusBadGateway, "Could not list publisher files on Kaggle")
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		problem(w, http.StatusBadGateway, fmt.Sprintf("Kaggle file listing returned HTTP %d", response.StatusCode))
		return
	}
	var listing struct {
		Files []struct {
			Name string `json:"name"`
			Size int64  `json:"totalBytes"`
		} `json:"datasetFiles"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&listing); err != nil {
		problem(w, http.StatusBadGateway, "Kaggle returned an unsupported file-list response")
		return
	}
	files := []map[string]any{}
	for _, file := range listing.Files {
		if strings.HasSuffix(file.Name, ".csv") || strings.HasSuffix(file.Name, ".csv.gz") {
			files = append(files, map[string]any{"name": file.Name, "size": file.Size, "within_limit": file.Size <= datasets.MaxPayloadBytes})
		}
	}
	respond(w, http.StatusOK, map[string]any{"files": files, "public_access": true, "publisher": "icsdataset/hai-security-dataset"})
}

func (s *Server) train(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Domain    string `json:"domain"`
		DatasetID string `json:"dataset_id"`
	}
	if !decode(w, r, &input) {
		return
	}
	if !s.training.TryLock() {
		problem(w, http.StatusConflict, "A model training run is already in progress")
		return
	}
	defer s.training.Unlock()
	events, err := s.Store.Events(r.Context(), 200000)
	if err != nil {
		problem(w, http.StatusInternalServerError, "Could not load training evidence")
		return
	}
	model, err := research.Train(events, input.Domain, input.DatasetID)
	if err != nil {
		problem(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Store.Put(r.Context(), "model/"+input.Domain, model); err != nil {
		problem(w, http.StatusInternalServerError, "Could not persist model")
		return
	}
	model.Trees = nil
	s.changed()
	respond(w, http.StatusOK, model)
}

func (s *Server) checkAI(w http.ResponseWriter, r *http.Request) {
	if err := s.Analyst.Check(r.Context()); err != nil {
		_ = s.Store.Put(r.Context(), "ai_health", map[string]any{"connected": false, "checked_at": time.Now().UTC(), "error": err.Error()})
		problem(w, http.StatusBadGateway, err.Error())
		return
	}
	_ = s.Store.Put(r.Context(), "ai_health", map[string]any{"connected": true, "checked_at": time.Now().UTC()})
	respond(w, http.StatusOK, map[string]any{"connected": true, "provider": s.Config.AIProvider, "model": s.Config.AIModel})
}

func (s *Server) exportModel(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("domain")
	if kind != "authentication" && kind != "ics" {
		problem(w, http.StatusBadRequest, "Unknown model domain")
		return
	}
	var model research.Model
	if err := s.Store.Get(r.Context(), "model/"+kind, &model); err != nil {
		problem(w, http.StatusNotFound, "Train a model before exporting")
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="identityshield-`+kind+`-model.json"`)
	respond(w, http.StatusOK, model)
}

func (s *Server) exportEvents(w http.ResponseWriter, r *http.Request) {
	events, err := s.Store.Events(r.Context(), 200000)
	if err != nil {
		problem(w, http.StatusInternalServerError, "Could not export evidence")
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="identityshield-evidence.jsonl"`)
	encoder := json.NewEncoder(w)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return
		}
	}
}

func (s *Server) exportReport(w http.ResponseWriter, r *http.Request) {
	incident, _, err := s.investigation(r.Context(), r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusNotFound, "Investigation not found")
		return
	}
	report, err := s.Store.Report(r.Context(), incident.ID)
	if err != nil || report.EvidenceHash != incident.EvidenceHash {
		problem(w, http.StatusNotFound, "Generate a report for the current evidence before exporting")
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+incident.ID+`-report.md"`)
	fmt.Fprintf(w, "# %s\n\n**Case:** %s · **Provider:** %s · **Model:** %s\n\n## Summary\n\n%s\n\n**Suggested verdict:** %s\n\n## Evidence-backed findings\n\n", incident.Title, incident.ID, report.Provider, report.Model, report.Summary, report.Verdict)
	for _, claim := range report.Claims {
		fmt.Fprintf(w, "- %s [%s]\n", claim.Text, strings.Join(claim.EvidenceIDs, ", "))
	}
	fmt.Fprint(w, "\n## Next steps\n\n")
	for _, step := range report.NextSteps {
		fmt.Fprintf(w, "- %s\n", step)
	}
	fmt.Fprint(w, "\n## Limitations\n\n")
	for _, limitation := range report.Limitations {
		fmt.Fprintf(w, "- %s\n", limitation)
	}
	fmt.Fprintf(w, "\nEvidence digest: `%s`\n", report.EvidenceHash)
}

func (s *Server) changed() {
	s.revision.Add(1)
	select {
	case s.changes <- struct{}{}:
	default:
	}
}

func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		problem(w, http.StatusInternalServerError, "Streaming is not available")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Cache-Control", "no-cache")
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	fmt.Fprint(w, "event: ready\ndata: {}\n\n")
	flusher.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.changes:
			fmt.Fprint(w, "event: change\ndata: {}\n\n")
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, "event: heartbeat\ndata: {\"time\":%q}\n\n", time.Now().UTC().Format(time.RFC3339))
			flusher.Flush()
		}
	}
}
