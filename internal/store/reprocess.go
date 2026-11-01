package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/YeandAmen/identityshield/internal/domain"
)

// Reprocess updates normalization from preserved originals while retaining
// independent label reviews. Identity and raw hashes must match the old record.
func (s *Store) Reprocess(ctx context.Context, datasetID string, normalized []domain.Event) (int, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	updated := 0
	for _, event := range normalized {
		var raw string
		err := tx.QueryRowContext(ctx, `SELECT data FROM events WHERE id=? AND dataset_id=?`, event.ID, datasetID).Scan(&raw)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return 0, err
		}
		var old domain.Event
		if err := json.Unmarshal([]byte(raw), &old); err != nil {
			return 0, err
		}
		if old.RawSHA256 != event.RawSHA256 {
			return 0, fmt.Errorf("original evidence hash mismatch for %s", event.ID)
		}
		event.DatasetID, event.Label = datasetID, old.Label
		for key, value := range old.Data {
			if strings.HasPrefix(key, "label_") {
				event.Data[key] = value
			}
		}
		encoded, err := json.Marshal(event)
		if err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE events SET occurred_at=?,actor=?,kind=?,run_id=?,data=? WHERE id=? AND dataset_id=?`, event.Timestamp.UTC().Format(time.RFC3339Nano), event.Actor, event.Kind, event.RunID, string(encoded), event.ID, datasetID); err != nil {
			return 0, err
		}
		updated++
	}
	return updated, tx.Commit()
}
