package store_test

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/YeandAmen/underdog/internal/domain"
	"github.com/YeandAmen/underdog/internal/store"
)

func TestReportQueueDeduplicatesAndClaimsOnce(t *testing.T) {
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	first, err := db.EnqueueReport(ctx, "CASE-1", "digest", "agentrouter", "gpt-6.1-sol")
	if err != nil {
		t.Fatal(err)
	}
	second, err := db.EnqueueReport(ctx, "CASE-1", "digest", "agentrouter", "gpt-6.1-sol")
	if err != nil || second.ID != first.ID {
		t.Fatal("duplicate Generate requests created different active jobs")
	}
	var workers sync.WaitGroup
	claimed := make(chan string, 4)
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			job, token, err := db.ClaimReport(ctx, "agentrouter", "gpt-6.1-sol")
			if err == nil && job.ID == first.ID && token != "" {
				claimed <- job.ID
			} else if !errors.Is(err, sql.ErrNoRows) {
				t.Errorf("claim failed: %v", err)
			}
		}()
	}
	workers.Wait()
	close(claimed)
	if len(claimed) != 1 {
		t.Fatalf("concurrent workers claimed the same job %d times", len(claimed))
	}
}

func TestExpiredClaimCannotPublishAndCompletionIsDurable(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, err = db.EnqueueReport(ctx, "CASE-1", "digest", "agentrouter", "gpt-6.1-sol")
	if err != nil {
		t.Fatal(err)
	}
	job, oldToken, err := db.ClaimReport(ctx, "agentrouter", "gpt-6.1-sol")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.DB.ExecContext(ctx, `UPDATE report_jobs SET lease_until=? WHERE id=?`, time.Now().Add(-time.Second).UTC().Format("2006-01-02T15:04:05.000000000Z"), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	claimed, token, err := db.ClaimReport(ctx, "agentrouter", "gpt-6.1-sol")
	if err != nil || token == oldToken || claimed.Attempts != 2 {
		t.Fatalf("expired work was not recovered with a fresh lease: %#v %v", claimed, err)
	}
	report := domain.Report{IncidentID: job.IncidentID, EvidenceHash: job.EvidenceHash, Provider: job.Provider, Model: job.Model, Summary: "Observed activity", GeneratedAt: time.Now().UTC()}
	if _, err := db.FinishReportJob(ctx, job.ID, oldToken, &report, ""); !errors.Is(err, store.ErrJobLease) {
		t.Fatal("an expired worker was allowed to publish")
	}
	bad := report
	bad.EvidenceHash = "different-evidence"
	if _, err := db.FinishReportJob(ctx, job.ID, token, &bad, ""); err == nil {
		t.Fatal("mismatched report metadata was accepted")
	}
	current, _ := db.ReportJob(ctx, job.ID)
	if current.Status != "running" {
		t.Fatal("a failed transaction left a partially completed job")
	}
	finished, err := db.FinishReportJob(ctx, job.ID, token, &report, "")
	if err != nil || finished.Status != "succeeded" {
		t.Fatalf("valid report was not saved: %#v %v", finished, err)
	}
	if _, err := db.FinishReportJob(ctx, job.ID, token, &report, ""); err != nil {
		t.Fatal("completion retry was not idempotent")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	saved, err := db.Report(ctx, job.IncidentID)
	if err != nil || saved.Summary != report.Summary {
		t.Fatal("completed report was lost after reopening storage")
	}
	result, err := db.ReportJobResult(ctx, job.ID)
	if err != nil || result.EvidenceHash != job.EvidenceHash {
		t.Fatal("job result was not persisted with its completion")
	}
}
