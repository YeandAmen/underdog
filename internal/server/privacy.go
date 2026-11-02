package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/YeandAmen/underdog/internal/analyst"
	"github.com/YeandAmen/underdog/internal/domain"
)

const publicAnomalySummary = "Activity differs from the usual pattern. Review the incident evidence and access context before deciding whether it is a threat."

func (s *Server) researchAccess(r *http.Request) bool {
	if !s.Config.PublicAccess && s.Config.AccessToken == "" {
		return true // Local, private workspace.
	}
	token, bearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return s.Config.AccessToken != "" && bearer && subtle.ConstantTimeCompare([]byte(token), []byte(s.Config.AccessToken)) == 1
}

func researchEndpoint(r *http.Request) bool {
	path := r.URL.Path
	return path == "/api/events" || strings.HasPrefix(path, "/api/events/") ||
		strings.HasPrefix(path, "/api/datasets/") || strings.HasPrefix(path, "/api/research/") ||
		strings.HasPrefix(path, "/api/lab/") || path == "/api/export/events" ||
		strings.HasPrefix(path, "/api/export/model/") || path == "/api/identity/snapshot" ||
		(strings.HasPrefix(path, "/api/incidents/") && strings.HasSuffix(path, "/review")) ||
		(r.Method == http.MethodPost && strings.HasPrefix(path, "/api/rules/"))
}

// Public citations are stable aliases, without collection names or truth labels
// encoded in the private event identifiers.
func (s *Server) publicEventID(id string) string {
	mac := hmac.New(sha256.New, []byte(s.Config.AccessToken))
	mac.Write([]byte("public-evidence:" + id))
	return "EVT-" + hex.EncodeToString(mac.Sum(nil)[:12])
}

func (s *Server) publicText(text string, events []domain.Event) string {
	for _, event := range events {
		if event.ID != "" {
			text = strings.ReplaceAll(text, event.ID, s.publicEventID(event.ID))
		}
	}
	return text
}

func (s *Server) publicIncident(incident domain.Incident) map[string]any {
	ids := make([]string, len(incident.EventIDs))
	for i, id := range incident.EventIDs {
		ids[i] = s.publicEventID(id)
	}
	summary := incident.Summary
	if strings.HasPrefix(incident.RuleID, "ML-") {
		summary = publicAnomalySummary
	}
	return map[string]any{
		"id": incident.ID, "title": incident.Title, "summary": summary,
		"rule_id": incident.RuleID, "technique": incident.Technique,
		"severity": incident.Severity, "priority": incident.Priority,
		"actor": incident.Actor, "host": incident.Host,
		"started_at": incident.StartedAt, "last_seen": incident.LastSeen,
		"time_basis": incident.TimeBasis, "status": incident.Status,
		"event_ids": ids, "findings": incident.Findings,
		"policy_aware": incident.PolicyAware, "evidence_hash": incident.EvidenceHash,
	}
}

func (s *Server) publicEvents(events []domain.Event) []map[string]any {
	allowed := map[string]bool{
		"command": true, "image": true, "process_name": true, "parent_image": true,
		"source_ip": true, "destination_ip": true, "ip": true, "logon_type": true,
		"status": true, "result": true, "event_id": true, "group": true,
		"member": true, "privilege": true, "service": true, "task": true,
		"tank_level": true, "pressure": true, "flow_rate": true,
	}
	rows := make([]map[string]any, 0, len(events))
	for _, event := range events {
		fields := map[string]string{}
		for key, value := range event.Data {
			if allowed[key] {
				fields[key] = s.publicText(value, events)
			}
		}
		rows = append(rows, map[string]any{
			"id": s.publicEventID(event.ID), "timestamp": event.Timestamp,
			"kind": event.Kind, "actor": event.Actor, "host": event.Host,
			"source_host": event.SourceHost, "target": event.Target, "data": fields,
		})
	}
	return rows
}

func (s *Server) presentedReport(r *http.Request, report domain.Report, events []domain.Event) domain.Report {
	if s.researchAccess(r) {
		return report
	}
	if strings.HasPrefix(report.IncidentID, "MODEL-") {
		generated := report.GeneratedAt
		report = analyst.Template(domain.Incident{ID: report.IncidentID, Summary: publicAnomalySummary, EvidenceHash: report.EvidenceHash}, events)
		report.GeneratedAt, report.Verdict = generated, "insufficient_evidence"
	}
	if report.Provider != "local" {
		report.Provider, report.Model = "our-model", "our-model"
	}
	report.Summary = s.publicText(report.Summary, events)
	claims := make([]domain.Claim, len(report.Claims))
	for i, claim := range report.Claims {
		ids := make([]string, len(claim.EvidenceIDs))
		for j, id := range claim.EvidenceIDs {
			ids[j] = s.publicEventID(id)
		}
		claims[i] = domain.Claim{Text: s.publicText(claim.Text, events), EvidenceIDs: ids}
	}
	report.Claims = claims
	for _, pair := range []struct {
		input  []string
		output *[]string
	}{{report.NextSteps, &report.NextSteps}, {report.Limitations, &report.Limitations}} {
		values := make([]string, len(pair.input))
		for i, text := range pair.input {
			values[i] = s.publicText(text, events)
		}
		*pair.output = values
	}
	return report
}

func (s *Server) presentedJob(r *http.Request, job domain.ReportJob) any {
	if s.researchAccess(r) {
		return job
	}
	message := ""
	if job.Status == "failed" {
		message = "Our model could not complete this report. Please retry."
	}
	return map[string]any{
		"id": job.ID, "incident_id": job.IncidentID, "status": job.Status,
		"created_at": job.CreatedAt, "updated_at": job.UpdatedAt,
		"evidence_hash": job.EvidenceHash, "error": message,
	}
}
