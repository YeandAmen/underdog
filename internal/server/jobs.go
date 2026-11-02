package server

import (
	"crypto/subtle"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/YeandAmen/underdog/internal/analyst"
	"github.com/YeandAmen/underdog/internal/domain"
	"github.com/YeandAmen/underdog/internal/store"
)

func (s *Server) workerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/ai/worker/status", s.workerStatus)
	mux.HandleFunc("GET /api/report-jobs/{id}", s.reportJob)
	mux.Handle("POST /api/ai/worker/heartbeat", s.workerOnly(http.HandlerFunc(s.workerHeartbeat)))
	mux.Handle("POST /api/ai/worker/claim", s.workerOnly(http.HandlerFunc(s.claimReport)))
	mux.Handle("POST /api/ai/worker/jobs/{id}/complete", s.workerOnly(http.HandlerFunc(s.completeReport)))
}

func (s *Server) workerOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, bearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if s.Config.WorkerToken == "" || !bearer || subtle.ConstantTimeCompare([]byte(token), []byte(s.Config.WorkerToken)) != 1 {
			problem(w, http.StatusUnauthorized, "Report worker authentication required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) workerStatus(w http.ResponseWriter, r *http.Request) {
	respond(w, http.StatusOK, s.Store.WorkerStatus(r.Context()))
}

func (s *Server) workerHeartbeat(w http.ResponseWriter, r *http.Request) {
	if !s.verifyWorker(w, r) {
		return
	}
	respond(w, http.StatusOK, s.Store.WorkerStatus(r.Context()))
}

func (s *Server) verifyWorker(w http.ResponseWriter, r *http.Request) bool {
	var input struct {
		Provider string `json:"provider"`
		Model    string `json:"model"`
	}
	if !decode(w, r, &input) {
		return false
	}
	if input.Provider != s.Config.AIProvider || input.Model != s.Config.AIModel {
		problem(w, http.StatusConflict, "The worker must use the workspace's configured model and provider")
		return false
	}
	if err := s.Store.WorkerHeartbeat(r.Context()); err != nil {
		problem(w, http.StatusInternalServerError, "Could not update the report worker connection")
		return false
	}
	return true
}

func (s *Server) enqueueReport(w http.ResponseWriter, r *http.Request, incident domain.Incident) {
	if s.Config.WorkerToken == "" || !s.Store.WorkerStatus(r.Context()).Online {
		problem(w, http.StatusServiceUnavailable, "Our model worker is offline. Please retry when the project terminal reconnects.")
		return
	}
	job, err := s.Store.EnqueueReport(r.Context(), incident.ID, incident.EvidenceHash, s.Config.AIProvider, s.Config.AIModel)
	if err != nil {
		problem(w, http.StatusInternalServerError, "Could not queue the report")
		return
	}
	respond(w, http.StatusAccepted, map[string]any{"job": job})
}

func (s *Server) claimReport(w http.ResponseWriter, r *http.Request) {
	if !s.verifyWorker(w, r) {
		return
	}
	job, token, err := s.Store.ClaimReport(r.Context(), s.Config.AIProvider, s.Config.AIModel)
	if errors.Is(err, sql.ErrNoRows) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		problem(w, http.StatusInternalServerError, "Could not claim a report job")
		return
	}
	incident, events, err := s.investigation(r.Context(), job.IncidentID)
	if err != nil || incident.EvidenceHash != job.EvidenceHash {
		_, err = s.Store.FinishReportJob(r.Context(), job.ID, token, nil, "The incident evidence changed. Generate a new report.")
		if err != nil {
			problem(w, http.StatusInternalServerError, "Could not release the outdated report job")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	request, err := analyst.PrepareReport(incident, events)
	if err != nil {
		_, _ = s.Store.FinishReportJob(r.Context(), job.ID, token, nil, "The incident evidence could not be prepared.")
		problem(w, http.StatusInternalServerError, "Could not prepare the incident evidence")
		return
	}
	respond(w, http.StatusOK, domain.ReportTask{Job: job, ClaimToken: token, Request: request})
}

func (s *Server) completeReport(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ClaimToken string         `json:"claim_token"`
		Report     *domain.Report `json:"report"`
		Error      string         `json:"error"`
	}
	if !decode(w, r, &input) {
		return
	}
	if input.ClaimToken == "" || (input.Report == nil) == (strings.TrimSpace(input.Error) == "") || len(input.Error) > 1000 {
		problem(w, http.StatusBadRequest, "A claim token and either a report or a brief error are required")
		return
	}
	job, err := s.Store.ReportJob(r.Context(), r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusNotFound, "Report job not found")
		return
	}
	status := http.StatusOK
	if input.Report != nil {
		incident, events, err := s.investigation(r.Context(), job.IncidentID)
		if err != nil || incident.EvidenceHash != job.EvidenceHash {
			input.Report, input.Error, status = nil, "The incident evidence changed. Generate a new report.", http.StatusConflict
		} else if err := analyst.Validate(*input.Report, events); err != nil {
			input.Report, input.Error, status = nil, err.Error(), http.StatusUnprocessableEntity
		} else {
			input.Report.IncidentID, input.Report.EvidenceHash = job.IncidentID, job.EvidenceHash
			input.Report.Provider, input.Report.Model = job.Provider, job.Model
			input.Report.GeneratedAt = time.Now().UTC()
		}
	}
	completed, err := s.Store.FinishReportJob(r.Context(), job.ID, input.ClaimToken, input.Report, input.Error)
	if errors.Is(err, store.ErrJobLease) {
		problem(w, http.StatusConflict, "This report job's lease expired or belongs to another worker")
		return
	}
	if err != nil {
		problem(w, http.StatusInternalServerError, "Could not save the report job")
		return
	}
	if status != http.StatusOK {
		problem(w, status, input.Error)
		return
	}
	respond(w, http.StatusOK, map[string]any{"job": completed})
}

func (s *Server) reportJob(w http.ResponseWriter, r *http.Request) {
	job, err := s.Store.ReportJob(r.Context(), r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusNotFound, "Report job not found")
		return
	}
	response := map[string]any{"job": job, "worker": s.Store.WorkerStatus(r.Context())}
	if job.Status == "succeeded" {
		incident, events, err := s.investigation(r.Context(), job.IncidentID)
		if err != nil || incident.EvidenceHash != job.EvidenceHash {
			problem(w, http.StatusConflict, "The incident evidence changed. Generate a new report.")
			return
		}
		report, err := s.Store.ReportJobResult(r.Context(), job.ID)
		if err != nil || analyst.Validate(report, events) != nil {
			problem(w, http.StatusInternalServerError, "The validated report could not be loaded")
			return
		}
		response["report"] = report
	}
	respond(w, http.StatusOK, response)
}
