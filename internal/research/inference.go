package research

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/YeandAmen/identityshield/internal/domain"
	"github.com/YeandAmen/identityshield/internal/identity"
)

// Infer applies the persisted forest to feature-compatible windows. Labels are
// retained only as evaluation metadata; they never enter scoring or thresholds.
func Infer(model Model, events []domain.Event, snapshot domain.Snapshot) []domain.Incident {
	compatible := []domain.Event{}
	for _, event := range events {
		if model.Domain == "authentication" && (event.Kind == "auth_success" || event.Kind == "auth_failure") {
			compatible = append(compatible, event)
		} else if model.Domain == "ics" && event.Kind == "ics_sample" && event.Data["schema"] == model.Schema {
			compatible = append(compatible, event)
		}
	}
	samples, names, _, err := BuildSamples(compatible, model.Domain)
	if err != nil || !reflect.DeepEqual(names, model.FeatureNames) {
		return []domain.Incident{}
	}
	byID := map[string]domain.Event{}
	for _, event := range compatible {
		byID[event.ID] = event
	}
	findings := identity.Audit(snapshot)
	incidents := []domain.Incident{}
	for _, sample := range samples {
		score := model.Score(sample.Features)
		if score <= model.Threshold {
			continue
		}
		first, exists := byID[sample.EventIDs[0]]
		if !exists {
			continue
		}
		last := first.Timestamp
		for _, id := range sample.EventIDs {
			if event := byID[id]; event.Timestamp.After(last) {
				last = event.Timestamp
			}
		}
		hash := sha256.Sum256([]byte(model.DataHash + "|" + model.Domain + "|" + sample.Group + "|" + first.Actor + "|" + sample.Time.Format(time.RFC3339)))
		name := "Authentication outside the learned baseline"
		if model.Domain == "ics" {
			name = "Industrial telemetry outside the learned baseline"
		}
		incident := domain.Incident{
			ID: fmt.Sprintf("MODEL-%x", hash[:4]), Title: name, RuleID: "ML-" + strings.ToUpper(model.Domain),
			Summary:  fmt.Sprintf("A five-minute %s window scored %.3f against the persisted validation threshold %.3f. This is an anomalous pattern, not a confirmed attack.", model.Domain, score, model.Threshold),
			Severity: "medium", Priority: min(74, 54+int((score-model.Threshold)*100)), Actor: first.Actor, Host: first.Host,
			StartedAt: sample.Time, LastSeen: last, Status: "open", GroundTruth: sample.Label, EventIDs: sample.EventIDs,
			TimeBasis: first.Data["time_basis"],
			Findings:  []domain.Finding{}, PolicyAware: identity.ContextApplies(snapshot, first.Source),
			Context: []string{fmt.Sprintf("Persisted %s model · %s · %d benign training windows.", model.Domain, model.ID, model.TrainingWindows), "Anomaly ranking is not calibrated probability. Performance on a new source is not established by the training-corpus benchmark."},
		}
		if user, ok := identity.FindUser(snapshot, first.Actor); ok && identity.ContextApplies(snapshot, first.Source) {
			incident.Context = append(incident.Context, "Approved role: "+user.Role)
			for _, finding := range findings {
				if finding.UserID == user.ID {
					incident.Findings = append(incident.Findings, finding)
				}
			}
		}
		incidents = append(incidents, incident)
	}
	return incidents
}

func Rank(incidents []domain.Incident) {
	sort.Slice(incidents, func(i, j int) bool {
		if incidents[i].Priority != incidents[j].Priority {
			return incidents[i].Priority > incidents[j].Priority
		}
		if incidents[i].LastSeen.Equal(incidents[j].LastSeen) {
			return incidents[i].ID < incidents[j].ID
		}
		return incidents[i].LastSeen.After(incidents[j].LastSeen)
	})
}
