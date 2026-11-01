package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
)

func (s *Store) PutPayload(ctx context.Context, dir, hash string, payload []byte) error {
	if s.DB.Postgres {
		_, err := s.DB.ExecContext(ctx, `INSERT INTO payloads(sha256,data) VALUES(?,?) ON CONFLICT(sha256) DO NOTHING`, hash, payload)
		return err
	}
	if err := os.MkdirAll(filepath.Join(dir, "imports"), 0700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "imports", hash+".payload"), payload, 0600)
}
func (s *Store) Payload(ctx context.Context, dir, hash string) ([]byte, error) {
	if s.DB.Postgres {
		var payload []byte
		err := s.DB.QueryRowContext(ctx, `SELECT data FROM payloads WHERE sha256=?`, hash).Scan(&payload)
		if err == sql.ErrNoRows {
			rows, e := s.DB.QueryContext(ctx, `SELECT data FROM payload_chunks WHERE sha256=? ORDER BY chunk_index`, hash)
			if e != nil {
				return nil, e
			}
			defer rows.Close()
			for rows.Next() {
				var chunk []byte
				if e := rows.Scan(&chunk); e != nil {
					return nil, e
				}
				payload = append(payload, chunk...)
			}
			if len(payload) > 0 {
				return payload, rows.Err()
			}
		}
		return payload, err
	}
	return os.ReadFile(filepath.Join(dir, "imports", hash+".payload"))
}
