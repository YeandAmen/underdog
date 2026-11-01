package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/YeandAmen/identityshield/internal/store"
)

func neonSQL(ctx context.Context, databaseURL, query string, params []any) error {
	u, err := url.Parse(databaseURL)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{"query": query, "params": params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", "https://"+u.Hostname()+"/sql", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Neon-Connection-String", databaseURL)
	req.Header.Set("Neon-Raw-Text-Output", "true")
	resp, err := (&http.Client{Timeout: 90 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("Neon HTTPS SQL returned HTTP %d: %s", resp.StatusCode, string(data))
	}
	return nil
}

func migratePayloads(ctx context.Context, databaseURL string) error {
	if err := neonSQL(ctx, databaseURL, `CREATE TABLE IF NOT EXISTS payload_chunks(sha256 TEXT NOT NULL,chunk_index INTEGER NOT NULL,data BYTEA NOT NULL,PRIMARY KEY(sha256,chunk_index))`, []any{}); err != nil {
		return err
	}
	source, err := store.Open("data")
	if err != nil {
		return err
	}
	defer source.Close()
	datasets, err := source.Datasets(ctx)
	if err != nil {
		return err
	}
	for _, dataset := range datasets {
		payload, err := source.Payload(ctx, "data", dataset.SHA256)
		if err != nil {
			continue
		}
		for start, index := 0, 0; start < len(payload); start, index = start+(512<<10), index+1 {
			end := min(start+(512<<10), len(payload))
			if err := neonSQL(ctx, databaseURL, `INSERT INTO payload_chunks(sha256,chunk_index,data) VALUES($1,$2,decode($3,'base64')) ON CONFLICT(sha256,chunk_index) DO NOTHING`, []any{dataset.SHA256, index, base64.StdEncoding.EncodeToString(payload[start:end])}); err != nil {
				return err
			}
		}
		fmt.Printf("Persisted original payload: %s (%d bytes)\n", dataset.Name, len(payload))
	}
	return nil
}

func migrateHTTP(ctx context.Context, databaseURL string, metadataOnly bool, eventOffset int) error {
	source, err := store.Open("data")
	if err != nil {
		return err
	}
	defer source.Close()
	schema := `CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY,occurred_at TEXT NOT NULL,source TEXT NOT NULL,dataset_id TEXT NOT NULL,run_id TEXT NOT NULL,actor TEXT NOT NULL,kind TEXT NOT NULL,label TEXT NOT NULL,data TEXT NOT NULL);CREATE INDEX IF NOT EXISTS events_time ON events(occurred_at);CREATE INDEX IF NOT EXISTS events_dataset ON events(dataset_id);CREATE TABLE IF NOT EXISTS datasets (id TEXT PRIMARY KEY,data TEXT NOT NULL);CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY,value TEXT NOT NULL);CREATE TABLE IF NOT EXISTS reports (incident_id TEXT PRIMARY KEY,data TEXT NOT NULL);CREATE TABLE IF NOT EXISTS reviews (incident_id TEXT PRIMARY KEY,data TEXT NOT NULL);CREATE TABLE IF NOT EXISTS workspace_revision (id INTEGER PRIMARY KEY,value BIGINT NOT NULL);INSERT INTO workspace_revision(id,value) VALUES(1,0) ON CONFLICT(id) DO NOTHING;CREATE TABLE IF NOT EXISTS payloads(sha256 TEXT PRIMARY KEY,data BYTEA NOT NULL)`
	for _, query := range strings.Split(schema, ";") {
		if err := neonSQL(ctx, databaseURL, query, []any{}); err != nil {
			return err
		}
	}
	events, err := source.Events(ctx, 200000)
	if err != nil {
		return err
	}
	for start := eventOffset; start < len(events); start += 1000 {
		if metadataOnly {
			break
		}
		end := min(start+1000, len(events))
		values := []string{}
		params := []any{}
		for _, event := range events[start:end] {
			data, err := json.Marshal(event)
			if err != nil {
				return err
			}
			offset := len(params)
			parts := []string{}
			for n := 1; n <= 9; n++ {
				parts = append(parts, fmt.Sprintf("$%d", offset+n))
			}
			values = append(values, "("+strings.Join(parts, ",")+")")
			params = append(params, event.ID, event.Timestamp.UTC().Format(time.RFC3339Nano), event.Source, event.DatasetID, event.RunID, event.Actor, event.Kind, event.Label, string(data))
		}
		if err := neonSQL(ctx, databaseURL, `INSERT INTO events(id,occurred_at,source,dataset_id,run_id,actor,kind,label,data) VALUES `+strings.Join(values, ",")+` ON CONFLICT(id) DO NOTHING`, params); err != nil {
			return err
		}
		if start%2000 == 0 {
			fmt.Printf("Persisted events: %d/%d\n", end, len(events))
		}
	}
	for _, table := range []string{"datasets", "state", "reports", "reviews"} {
		key, value := "id", "data"
		if table == "state" {
			key, value = "key", "value"
		}
		if table == "reports" || table == "reviews" {
			key = "incident_id"
		}
		rows, err := source.DB.QueryContext(ctx, "SELECT "+key+","+value+" FROM "+table)
		if err != nil {
			return err
		}
		for rows.Next() {
			var k, v string
			if err := rows.Scan(&k, &v); err != nil {
				rows.Close()
				return err
			}
			if err := neonSQL(ctx, databaseURL, "INSERT INTO "+table+"("+key+","+value+") VALUES($1,$2) ON CONFLICT("+key+") DO UPDATE SET "+value+"=excluded."+value, []any{k, v}); err != nil {
				rows.Close()
				return err
			}
		}
		rows.Close()
	}
	fmt.Println("Evidence, manifests, policies, models, and reviews migrated to durable Neon storage.")
	return neonSQL(ctx, databaseURL, "UPDATE workspace_revision SET value=value+1 WHERE id=1", []any{})
}
