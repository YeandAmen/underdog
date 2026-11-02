package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/YeandAmen/underdog/internal/analyst"
	"github.com/YeandAmen/underdog/internal/domain"
	"github.com/YeandAmen/underdog/internal/store"
)

func publishReport(ctx context.Context, databaseURL, accessToken, incidentID string) error {
	if incidentID == "" || databaseURL == "" {
		return fmt.Errorf("publish-report requires -incident and the ignored Neon DATABASE_URL")
	}
	source, err := store.Open("data")
	if err != nil {
		return err
	}
	defer source.Close()
	report, err := source.Report(ctx, incidentID)
	if err != nil {
		return fmt.Errorf("load the locally generated report: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, productionURL+"/api/incidents/"+url.PathEscape(incidentID), nil)
	if err != nil {
		return err
	}
	if accessToken != "" {
		request.Header.Set("Authorization", "Bearer "+accessToken)
	}
	response, err := (&http.Client{Timeout: 90 * time.Second}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("verify the production evidence: HTTP %d", response.StatusCode)
	}
	var evidence struct {
		Incident domain.Incident `json:"incident"`
		Events   []domain.Event  `json:"events"`
	}
	if err := json.NewDecoder(response.Body).Decode(&evidence); err != nil {
		return err
	}
	if report.IncidentID != evidence.Incident.ID || report.EvidenceHash == "" || report.EvidenceHash != evidence.Incident.EvidenceHash {
		return fmt.Errorf("local and production evidence differ; report was not published")
	}
	if err := analyst.Validate(report, evidence.Events); err != nil {
		return err
	}
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	if err := neonSQL(ctx, databaseURL, "INSERT INTO reports(incident_id,data) VALUES($1,$2) ON CONFLICT(incident_id) DO UPDATE SET data=excluded.data", []any{incidentID, string(data)}); err != nil {
		return err
	}
	fmt.Printf("Published %s report for %s: model %s; %d validated claims; production evidence digest matched\n", report.Provider, incidentID, report.Model, len(report.Claims))
	return nil
}
