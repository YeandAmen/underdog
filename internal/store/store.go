package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/YeandAmen/identityshield/internal/domain"
	_ "modernc.org/sqlite"
)

type Store struct{ DB *sql.DB }

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "identityshield.db"))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
		CREATE TABLE IF NOT EXISTS events (
		id TEXT PRIMARY KEY, occurred_at TEXT NOT NULL, source TEXT NOT NULL,
		dataset_id TEXT NOT NULL, run_id TEXT NOT NULL, actor TEXT NOT NULL,
		kind TEXT NOT NULL, label TEXT NOT NULL, data TEXT NOT NULL);
		CREATE INDEX IF NOT EXISTS events_time ON events(occurred_at);
		CREATE INDEX IF NOT EXISTS events_dataset ON events(dataset_id);
		CREATE TABLE IF NOT EXISTS datasets (id TEXT PRIMARY KEY, data TEXT NOT NULL);
		CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
		CREATE TABLE IF NOT EXISTS reports (incident_id TEXT PRIMARY KEY, data TEXT NOT NULL);
		CREATE TABLE IF NOT EXISTS reviews (incident_id TEXT PRIMARY KEY, data TEXT NOT NULL);`)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{DB: db}, nil
}

func (s *Store) Close() error { return s.DB.Close() }

func (s *Store) Import(ctx context.Context, dataset domain.Dataset, events []domain.Event) (domain.Dataset, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return dataset, err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO events(id,occurred_at,source,dataset_id,run_id,actor,kind,label,data) VALUES(?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return dataset, err
	}
	defer stmt.Close()
	dataset.EventCount, dataset.BenignCount, dataset.MaliciousCount, dataset.UnknownCount = 0, 0, 0, 0
	for _, event := range events {
		event.DatasetID = dataset.ID
		if !domain.ValidLabel(event.Label) || event.Timestamp.IsZero() || event.ID == "" {
			return dataset, fmt.Errorf("event %q has an invalid label, timestamp, or ID", event.ID)
		}
		data, err := json.Marshal(event)
		if err != nil {
			return dataset, err
		}
		result, err := stmt.ExecContext(ctx, event.ID, event.Timestamp.UTC().Format(time.RFC3339Nano), event.Source, event.DatasetID, event.RunID, event.Actor, event.Kind, event.Label, string(data))
		if err != nil {
			return dataset, err
		}
		inserted, err := result.RowsAffected()
		if err != nil {
			return dataset, err
		}
		if inserted == 0 {
			continue
		}
		dataset.EventCount++
		switch event.Label {
		case "benign":
			dataset.BenignCount++
		case "malicious":
			dataset.MaliciousCount++
		default:
			dataset.UnknownCount++
		}
	}
	if dataset.EventCount == 0 {
		return dataset, fmt.Errorf("no new events: this evidence may already be imported")
	}
	data, err := json.Marshal(dataset)
	if err != nil {
		return dataset, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO datasets(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, dataset.ID, string(data)); err != nil {
		return dataset, err
	}
	return dataset, tx.Commit()
}

func (s *Store) Events(ctx context.Context, limit int) ([]domain.Event, error) {
	if limit <= 0 {
		limit = 200000
	}
	// Select the most recent records, then return them chronologically.
	rows, err := s.DB.QueryContext(ctx, `SELECT data FROM (SELECT data,occurred_at,id FROM events ORDER BY occurred_at DESC,id DESC LIMIT ?) ORDER BY occurred_at,id`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []domain.Event{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var event domain.Event
		if err := json.Unmarshal([]byte(raw), &event); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) Datasets(ctx context.Context) ([]domain.Dataset, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT data FROM datasets ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Dataset{}
	for rows.Next() {
		var raw string
		var d domain.Dataset
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) Put(ctx context.Context, key string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO state(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, string(data))
	return err
}

func (s *Store) Get(ctx context.Context, key string, value any) error {
	var raw string
	if err := s.DB.QueryRowContext(ctx, `SELECT value FROM state WHERE key=?`, key).Scan(&raw); err != nil {
		return err
	}
	return json.Unmarshal([]byte(raw), value)
}

func (s *Store) PutReport(ctx context.Context, report domain.Report) error {
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO reports(incident_id,data) VALUES(?,?) ON CONFLICT(incident_id) DO UPDATE SET data=excluded.data`, report.IncidentID, string(data))
	return err
}

func (s *Store) Report(ctx context.Context, incidentID string) (domain.Report, error) {
	var raw string
	var report domain.Report
	err := s.DB.QueryRowContext(ctx, `SELECT data FROM reports WHERE incident_id=?`, incidentID).Scan(&raw)
	if err != nil {
		return report, err
	}
	return report, json.Unmarshal([]byte(raw), &report)
}

func (s *Store) PutReview(ctx context.Context, review domain.Review) error {
	data, err := json.Marshal(review)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO reviews(incident_id,data) VALUES(?,?) ON CONFLICT(incident_id) DO UPDATE SET data=excluded.data`, review.IncidentID, string(data))
	return err
}

func (s *Store) Reviews(ctx context.Context) (map[string]domain.Review, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT data FROM reviews`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]domain.Review{}
	for rows.Next() {
		var raw string
		var r domain.Review
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			return nil, err
		}
		out[r.IncidentID] = r
	}
	return out, rows.Err()
}

func (s *Store) LabelEvent(ctx context.Context, id, label, reviewer, reason string) error {
	if !domain.ValidLabel(label) || reviewer == "" || reason == "" {
		return fmt.Errorf("a valid label, reviewer, and reason are required")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw string
	if err := tx.QueryRowContext(ctx, `SELECT data FROM events WHERE id=?`, id).Scan(&raw); err != nil {
		return err
	}
	var event domain.Event
	if err := json.Unmarshal([]byte(raw), &event); err != nil {
		return err
	}
	event.Label = label
	if event.Data == nil {
		event.Data = map[string]string{}
	}
	event.Data["label_reviewer"] = reviewer
	event.Data["label_reason"] = reason
	event.Data["label_reviewed_at"] = time.Now().UTC().Format(time.RFC3339)
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE events SET label=?,data=? WHERE id=?`, label, string(data), id); err != nil {
		return err
	}
	// Keep the provenance manifest's label counts in sync with reviewed evidence.
	var datasetRaw string
	if err := tx.QueryRowContext(ctx, `SELECT data FROM datasets WHERE id=?`, event.DatasetID).Scan(&datasetRaw); err != nil {
		return err
	}
	var dataset domain.Dataset
	if err := json.Unmarshal([]byte(datasetRaw), &dataset); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(label='benign'),0),COALESCE(SUM(label='malicious'),0),COALESCE(SUM(label='unknown'),0) FROM events WHERE dataset_id=?`, event.DatasetID).Scan(&dataset.EventCount, &dataset.BenignCount, &dataset.MaliciousCount, &dataset.UnknownCount); err != nil {
		return err
	}
	datasetJSON, err := json.Marshal(dataset)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE datasets SET data=? WHERE id=?`, string(datasetJSON), event.DatasetID); err != nil {
		return err
	}
	return tx.Commit()
}
