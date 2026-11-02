package store

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/coder/websocket"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

type Database struct {
	*sql.DB
	Postgres bool
}

func bind(query string, postgres bool) string {
	if !postgres {
		return query
	}
	var out strings.Builder
	index := 1
	for _, char := range query {
		if char == '?' {
			fmt.Fprintf(&out, "$%d", index)
			index++
		} else {
			out.WriteRune(char)
		}
	}
	return out.String()
}

func (d *Database) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return d.DB.ExecContext(ctx, bind(query, d.Postgres), args...)
}
func (d *Database) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return d.DB.QueryContext(ctx, bind(query, d.Postgres), args...)
}
func (d *Database) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return d.DB.QueryRowContext(ctx, bind(query, d.Postgres), args...)
}
func (d *Database) BeginTx(ctx context.Context, options *sql.TxOptions) (*Transaction, error) {
	tx, err := d.DB.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return &Transaction{Tx: tx, postgres: d.Postgres}, nil
}

type Transaction struct {
	*sql.Tx
	postgres bool
}

func (t *Transaction) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return t.Tx.ExecContext(ctx, bind(query, t.postgres), args...)
}
func (t *Transaction) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return t.Tx.QueryContext(ctx, bind(query, t.postgres), args...)
}
func (t *Transaction) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return t.Tx.QueryRowContext(ctx, bind(query, t.postgres), args...)
}
func (t *Transaction) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	return t.Tx.PrepareContext(ctx, bind(query, t.postgres))
}

const schema = `CREATE TABLE IF NOT EXISTS events (
id TEXT PRIMARY KEY, occurred_at TEXT NOT NULL, source TEXT NOT NULL,
dataset_id TEXT NOT NULL, run_id TEXT NOT NULL, actor TEXT NOT NULL,
kind TEXT NOT NULL, label TEXT NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS events_time ON events(occurred_at);
CREATE INDEX IF NOT EXISTS events_dataset ON events(dataset_id);
CREATE TABLE IF NOT EXISTS datasets (id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reports (incident_id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reviews (incident_id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS report_jobs (
id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, evidence_hash TEXT NOT NULL,
provider TEXT NOT NULL, model TEXT NOT NULL, status TEXT NOT NULL,
created_at TEXT NOT NULL, updated_at TEXT NOT NULL, lease_until TEXT NOT NULL DEFAULT '',
claim_token TEXT NOT NULL DEFAULT '', attempts INTEGER NOT NULL DEFAULT 0,
error TEXT NOT NULL DEFAULT '', result TEXT NOT NULL DEFAULT '');
CREATE UNIQUE INDEX IF NOT EXISTS report_jobs_active ON report_jobs
(incident_id,evidence_hash,provider,model) WHERE status IN ('queued','running');
CREATE INDEX IF NOT EXISTS report_jobs_queue ON report_jobs(status,created_at);
CREATE TABLE IF NOT EXISTS workspace_revision (id INTEGER PRIMARY KEY, value BIGINT NOT NULL);
INSERT INTO workspace_revision(id,value) VALUES(1,0) ON CONFLICT(id) DO NOTHING;`

func OpenPostgres(ctx context.Context, databaseURL string) (*Store, error) {
	cfg, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(cfg.Host, ".neon.tech") && os.Getenv("IDENTITYSHIELD_NEON_WEBSOCKET") == "true" {
		host := cfg.Host
		cfg.TLSConfig = nil
		cfg.Fallbacks = nil
		cfg.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
			endpoint := url.URL{Scheme: "wss", Host: host, Path: "/v2"}
			conn, _, err := websocket.Dial(ctx, endpoint.String(), nil)
			if err != nil {
				return nil, err
			}
			return websocket.NetConn(ctx, conn, websocket.MessageBinary), nil
		}
	}
	raw := stdlib.OpenDB(*cfg)
	raw.SetMaxOpenConns(4)
	raw.SetMaxIdleConns(2)
	db := &Database{DB: raw, Postgres: true}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("connect persistent database: %w", err)
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS payloads (sha256 TEXT PRIMARY KEY, data BYTEA NOT NULL)`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS payload_chunks(sha256 TEXT NOT NULL,chunk_index INTEGER NOT NULL,data BYTEA NOT NULL,PRIMARY KEY(sha256,chunk_index))`); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{DB: db}, nil
}

func (s *Store) Revision(ctx context.Context) (uint64, error) {
	var revision uint64
	err := s.DB.QueryRowContext(ctx, `SELECT value FROM workspace_revision WHERE id=1`).Scan(&revision)
	return revision, err
}
func (s *Store) BumpRevision(ctx context.Context) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE workspace_revision SET value=value+1 WHERE id=1`)
	return err
}
