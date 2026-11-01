package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/YeandAmen/identityshield/internal/domain"
)

func (s *Store) importPostgres(ctx context.Context, dataset domain.Dataset, events []domain.Event) (domain.Dataset, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return dataset, err
	}
	defer tx.Rollback()
	dataset.EventCount, dataset.BenignCount, dataset.MaliciousCount, dataset.UnknownCount = 0, 0, 0, 0
	for start := 0; start < len(events); start += 200 {
		end := min(start+200, len(events))
		values := make([]string, 0, end-start)
		args := make([]any, 0, (end-start)*9)
		for _, event := range events[start:end] {
			event.DatasetID = dataset.ID
			if !domain.ValidLabel(event.Label) || event.Timestamp.IsZero() || event.ID == "" {
				return dataset, fmt.Errorf("invalid event %q", event.ID)
			}
			data, err := json.Marshal(event)
			if err != nil {
				return dataset, err
			}
			values = append(values, "(?,?,?,?,?,?,?,?,?)")
			args = append(args, event.ID, event.Timestamp.UTC().Format(time.RFC3339Nano), event.Source, event.DatasetID, event.RunID, event.Actor, event.Kind, event.Label, string(data))
		}
		rows, err := tx.QueryContext(ctx, `INSERT INTO events(id,occurred_at,source,dataset_id,run_id,actor,kind,label,data) VALUES `+strings.Join(values, ",")+` ON CONFLICT(id) DO NOTHING RETURNING label`, args...)
		if err != nil {
			return dataset, err
		}
		for rows.Next() {
			var label string
			if err := rows.Scan(&label); err != nil {
				rows.Close()
				return dataset, err
			}
			dataset.EventCount++
			switch label {
			case "benign":
				dataset.BenignCount++
			case "malicious":
				dataset.MaliciousCount++
			default:
				dataset.UnknownCount++
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return dataset, err
		}
		rows.Close()
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
