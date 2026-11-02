package domain

import "time"

type ReportJob struct {
	ID           string    `json:"id"`
	IncidentID   string    `json:"incident_id"`
	EvidenceHash string    `json:"evidence_hash"`
	Provider     string    `json:"provider"`
	Model        string    `json:"model"`
	Status       string    `json:"status"`
	Error        string    `json:"error,omitempty"`
	Attempts     int       `json:"attempts"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ModelRequest contains the same bounded, normalized evidence used by the
// direct analyst client. Raw payloads and truth labels never enter a job.
type ModelRequest struct {
	System string         `json:"system"`
	Input  string         `json:"input"`
	Schema map[string]any `json:"schema"`
}

type ReportTask struct {
	Job        ReportJob    `json:"job"`
	ClaimToken string       `json:"claim_token"`
	Request    ModelRequest `json:"request"`
}

type WorkerStatus struct {
	Online   bool       `json:"online"`
	LastSeen *time.Time `json:"last_seen,omitempty"`
}
