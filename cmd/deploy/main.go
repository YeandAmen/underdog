package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/YeandAmen/identityshield/internal/store"
)

func envFile(path string) map[string]string {
	values := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return values
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok {
			values[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), "\"'")
		}
	}
	return values
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	action := flag.String("action", "verify", "verify, migrate, or env")
	flag.Parse()
	local := envFile(".env")
	remote := envFile(".env.local")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	switch *action {
	case "check-web":
		cmd := exec.CommandContext(ctx, "npx", "--yes", "vercel", "curl", "/api/state", "--deployment", "https://identityshield.vercel.app", "--", "--silent", "--header", "Authorization: Bearer "+local["IDENTITYSHIELD_ACCESS_TOKEN"])
		output, err := cmd.Output()
		if err != nil {
			return err
		}
		var state struct {
			Counts map[string]int `json:"counts"`
			AI     map[string]any `json:"ai"`
			Models map[string]any `json:"models"`
		}
		if err := json.Unmarshal(output, &state); err != nil {
			return fmt.Errorf("deployment did not return a workspace response: %s", string(output[:min(500, len(output))]))
		}
		fmt.Printf("Deployed workspace: %d events; %d identities; provider %v; model %v; %d model domains\n", state.Counts["events"], state.Counts["identities"], state.AI["provider"], state.AI["model"], len(state.Models))
		return nil
	case "verify":
		req, _ := http.NewRequestWithContext(ctx, "GET", "https://www.kaggle.com/api/v1/datasets/list/icsdataset/hai-security-dataset?pageSize=20", nil)
		req.Header.Set("Authorization", "Bearer "+local["KAGGLE_API_TOKEN"])
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		fmt.Printf("Authenticated Kaggle response: HTTP %d\n", resp.StatusCode)
		if resp.StatusCode != 200 {
			return fmt.Errorf("Kaggle token rejected")
		}
		_, err = io.Copy(io.Discard, resp.Body)
		return err
	case "migrate":
		return migrateHTTP(ctx, remote["DATABASE_URL"], false, 0)
	case "migrate-meta":
		return migrateHTTP(ctx, remote["DATABASE_URL"], true, 0)
	case "migrate-tail":
		return migrateHTTP(ctx, remote["DATABASE_URL"], false, 24000)
	case "payloads":
		return migratePayloads(ctx, remote["DATABASE_URL"])
	case "migrate-tcp":
		if remote["DATABASE_URL"] == "" {
			return fmt.Errorf("Vercel DATABASE_URL is not available")
		}
		source, err := store.Open("data")
		if err != nil {
			return err
		}
		defer source.Close()
		target, err := store.OpenPostgres(ctx, remote["DATABASE_URL"])
		if err != nil {
			return err
		}
		defer target.Close()
		events, err := source.Events(ctx, 200000)
		if err != nil {
			return err
		}
		datasets, err := source.Datasets(ctx)
		if err != nil {
			return err
		}
		for _, dataset := range datasets {
			batch := events[:0:0]
			for _, event := range events {
				if event.DatasetID == dataset.ID {
					batch = append(batch, event)
				}
			}
			result, err := target.Import(ctx, dataset, batch)
			if err != nil && !strings.Contains(err.Error(), "no new events") {
				return err
			}
			fmt.Printf("Migrated %s: %d new events\n", dataset.Name, result.EventCount)
			payload, err := source.Payload(ctx, "data", dataset.SHA256)
			if err == nil {
				if err := target.PutPayload(ctx, "", dataset.SHA256, payload); err != nil {
					return err
				}
			}
		}
		for _, table := range []string{"state", "reports", "reviews"} {
			key := "key"
			value := "value"
			if table != "state" {
				key = "incident_id"
				value = "data"
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
				if _, err := target.DB.ExecContext(ctx, "INSERT INTO "+table+"("+key+","+value+") VALUES(?,?) ON CONFLICT("+key+") DO UPDATE SET "+value+"=excluded."+value, k, v); err != nil {
					rows.Close()
					return err
				}
			}
			rows.Close()
		}
		return target.BumpRevision(ctx)
	case "env":
		var token [32]byte
		if _, err := rand.Read(token[:]); err != nil {
			return err
		}
		access := hex.EncodeToString(token[:])
		if local["IDENTITYSHIELD_ACCESS_TOKEN"] != "" {
			access = local["IDENTITYSHIELD_ACCESS_TOKEN"]
		} else {
			f, err := os.OpenFile(".env", os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			fmt.Fprintln(f, "\nIDENTITYSHIELD_ACCESS_TOKEN="+access)
			f.Close()
		}
		values := map[string]string{"IDENTITYSHIELD_AI_PROVIDER": "agentrouter", "IDENTITYSHIELD_AI_MODEL": "gpt-6.1-sol", "IDENTITYSHIELD_AI_BASE_URL": "https://agentrouter.org/v1", "AGENT_ROUTER_BASE_URL": "https://agentrouter.org/v1", "AGENT_ROUTER_API_KEY": local["AGENT_ROUTER_API_KEY"], "KAGGLE_API_TOKEN": local["KAGGLE_API_TOKEN"], "IDENTITYSHIELD_ACCESS_TOKEN": access, "IDENTITYSHIELD_DEMO": "false"}
		for key, value := range values {
			cmd := exec.CommandContext(ctx, "npx", "--yes", "vercel", "env", "add", key, "production", "--force", "--yes")
			cmd.Stdin = bytes.NewBufferString(value)
			output, err := cmd.CombinedOutput()
			_ = output
			if err != nil {
				return fmt.Errorf("set production variable %s: %w", key, err)
			}
			fmt.Println("Configured server variable:", key)
		}
		return nil
	default:
		return fmt.Errorf("unknown action")
	}
}
