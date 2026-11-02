package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/YeandAmen/underdog/internal/domain"
)

const ReportJobLease = 8 * time.Minute

const jobColumns = "id,incident_id,evidence_hash,provider,model,status,error,attempts,created_at,updated_at"
const jobTimeFormat = "2006-01-02T15:04:05.000000000Z"

var ErrJobLease = errors.New("report job is no longer held by this worker")

func jobToken() (string, error) {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(token[:]), nil
}

func tokenDigest(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func scanJob(row interface{ Scan(...any) error }) (domain.ReportJob, error) {
	var job domain.ReportJob
	var created, updated string
	if err := row.Scan(&job.ID, &job.IncidentID, &job.EvidenceHash, &job.Provider, &job.Model, &job.Status, &job.Error, &job.Attempts, &created, &updated); err != nil {
		return job, err
	}
	var err error
	if job.CreatedAt, err = time.Parse(jobTimeFormat, created); err != nil {
		return job, err
	}
	job.UpdatedAt, err = time.Parse(jobTimeFormat, updated)
	return job, err
}

func (s *Store) EnqueueReport(ctx context.Context, incidentID, evidenceHash, provider, model string) (domain.ReportJob, error) {
	id, err := jobToken()
	if err != nil {
		return domain.ReportJob{}, err
	}
	now := time.Now().UTC().Format(jobTimeFormat)
	return scanJob(s.DB.QueryRowContext(ctx, `INSERT INTO report_jobs
(id,incident_id,evidence_hash,provider,model,status,created_at,updated_at)
VALUES(?,?,?,?,?,'queued',?,?)
ON CONFLICT(incident_id,evidence_hash,provider,model) WHERE status IN ('queued','running')
DO UPDATE SET updated_at=report_jobs.updated_at RETURNING `+jobColumns,
		"JOB-"+id[:24], incidentID, evidenceHash, provider, model, now, now))
}

func (s *Store) ReportJob(ctx context.Context, id string) (domain.ReportJob, error) {
	return scanJob(s.DB.QueryRowContext(ctx, `SELECT `+jobColumns+` FROM report_jobs WHERE id=?`, id))
}

func (s *Store) ReportJobResult(ctx context.Context, id string) (domain.Report, error) {
	var raw string
	var report domain.Report
	if err := s.DB.QueryRowContext(ctx, `SELECT result FROM report_jobs WHERE id=? AND status='succeeded'`, id).Scan(&raw); err != nil {
		return report, err
	}
	return report, json.Unmarshal([]byte(raw), &report)
}

func (s *Store) ActiveReportJob(ctx context.Context, incidentID, evidenceHash, provider, model string) (domain.ReportJob, error) {
	return scanJob(s.DB.QueryRowContext(ctx, `SELECT `+jobColumns+` FROM report_jobs
WHERE incident_id=? AND evidence_hash=? AND provider=? AND model=? AND status IN ('queued','running')`, incidentID, evidenceHash, provider, model))
}

// A conditional UPDATE is the claim lock on both SQLite and Postgres. Workers
// cannot claim the same lease, even across separate Vercel server instances.
func (s *Store) ClaimReport(ctx context.Context, provider, model string) (domain.ReportJob, string, error) {
	token, err := jobToken()
	if err != nil {
		return domain.ReportJob{}, "", err
	}
	now := time.Now().UTC()
	stamp := now.Format(jobTimeFormat)
	if _, err := s.DB.ExecContext(ctx, `UPDATE report_jobs SET status='failed',updated_at=?,error=?
WHERE status='running' AND lease_until<? AND attempts>=3`, stamp, "The report worker disconnected repeatedly. Generate the report again.", stamp); err != nil {
		return domain.ReportJob{}, "", err
	}
	job, err := scanJob(s.DB.QueryRowContext(ctx, `UPDATE report_jobs
SET status='running',updated_at=?,lease_until=?,claim_token=?,attempts=attempts+1
WHERE id=(SELECT id FROM report_jobs WHERE provider=? AND model=? AND attempts<3
AND (status='queued' OR (status='running' AND lease_until<?)) ORDER BY created_at,id LIMIT 1)
AND (status='queued' OR (status='running' AND lease_until<?)) RETURNING `+jobColumns,
		stamp, now.Add(ReportJobLease).Format(jobTimeFormat), tokenDigest(token), provider, model, stamp, stamp))
	return job, token, err
}

// Job completion and report persistence share a transaction. A stale claimant
// cannot overwrite a report produced by a worker that owns a renewed lease.
func (s *Store) FinishReportJob(ctx context.Context, id, token string, report *domain.Report, message string) (domain.ReportJob, error) {
	status := "failed"
	data := ""
	if report != nil {
		status, message = "succeeded", ""
		encoded, err := json.Marshal(report)
		if err != nil {
			return domain.ReportJob{}, err
		}
		data = string(encoded)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return domain.ReportJob{}, err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(jobTimeFormat)
	job, err := scanJob(tx.QueryRowContext(ctx, `UPDATE report_jobs SET status=?,error=?,updated_at=?,result=?
WHERE id=? AND status='running' AND claim_token=? AND lease_until>? RETURNING `+jobColumns,
		status, message, now, data, id, tokenDigest(token), now))
	if errors.Is(err, sql.ErrNoRows) {
		// Retrying after a lost HTTP response is idempotent for the same claimant.
		job, err = scanJob(tx.QueryRowContext(ctx, `SELECT `+jobColumns+` FROM report_jobs WHERE id=? AND status=? AND claim_token=?`, id, status, tokenDigest(token)))
		if errors.Is(err, sql.ErrNoRows) {
			err = ErrJobLease
		}
		return job, err
	}
	if err != nil {
		return domain.ReportJob{}, err
	}
	if report != nil {
		if report.IncidentID != job.IncidentID || report.EvidenceHash != job.EvidenceHash || report.Provider != job.Provider || report.Model != job.Model {
			return domain.ReportJob{}, errors.New("report metadata does not match its job")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO reports(incident_id,data) VALUES(?,?) ON CONFLICT(incident_id) DO UPDATE SET data=excluded.data`, report.IncidentID, data); err != nil {
			return domain.ReportJob{}, err
		}
	}
	return job, tx.Commit()
}

func (s *Store) WorkerHeartbeat(ctx context.Context) error {
	return s.Put(ctx, "ai_worker_heartbeat", time.Now().UTC())
}

func (s *Store) WorkerStatus(ctx context.Context) domain.WorkerStatus {
	var seen time.Time
	if s.Get(ctx, "ai_worker_heartbeat", &seen) != nil {
		return domain.WorkerStatus{}
	}
	age := time.Since(seen)
	return domain.WorkerStatus{Online: age >= -5*time.Second && age < 45*time.Second, LastSeen: &seen}
}
