package detection_test

import (
	"testing"
	"time"

	"github.com/YeandAmen/underdog/internal/detection"
	"github.com/YeandAmen/underdog/internal/domain"
	"github.com/YeandAmen/underdog/internal/lab"
)

func TestPolicyTuningRetainsMaliciousChange(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	events := append(lab.Scenario("benign-admin", "approved", now), lab.Scenario("identity-to-ot", "unapproved", now.Add(10*time.Minute))...)
	baseline := detection.Detect(events, lab.Snapshot(now), nil, false)
	contextual := detection.Detect(events, lab.Snapshot(now), nil, true)
	count := func(items []domain.Incident, label string) int {
		count := 0
		for _, item := range items {
			if item.RuleID == "IS-003" && item.GroundTruth == label {
				count++
			}
		}
		return count
	}
	if count(baseline, "benign") != 1 || count(contextual, "benign") != 0 || count(contextual, "malicious") != 1 {
		t.Fatalf("unexpected baseline/contextual outcomes: %#v / %#v", baseline, contextual)
	}
	for i := range events {
		events[i].Label = "unknown"
	}
	unknown := detection.Detect(events, lab.Snapshot(now), nil, true)
	if len(unknown) != len(contextual) {
		t.Fatal("ground-truth labels influenced detection decisions")
	}
}

func TestReplicationClientCorrelatesToLogonInsteadOfAuditHost(t *testing.T) {
	now := time.Now().UTC()
	snapshot := lab.Snapshot(now)
	snapshot.EventSources = []string{"windows"}
	login := domain.Event{ID: "login", Timestamp: now, Kind: "auth_success", Actor: "svc.backup", Host: "ns-dc01", SourceHost: "ns-ws01", Source: "windows", Label: "unknown", Data: map[string]string{"target_logon_id": "0x123"}}
	replication := domain.Event{ID: "replicate", Timestamp: now.Add(time.Second), Kind: "directory_replication", Actor: "svc.backup", Host: "ns-dc01", Source: "windows", Label: "unknown", Data: map[string]string{"subject_logon_id": "0x123"}}
	incidents := detection.Detect([]domain.Event{replication, login}, snapshot, nil, true)
	found := false
	for _, incident := range incidents {
		found = found || incident.RuleID == "IS-004"
	}
	if !found {
		t.Fatal("replication client was confused with the domain-controller audit host")
	}
	login.SourceHost = "ns-dc01"
	for _, incident := range detection.Detect([]domain.Event{login, replication}, snapshot, nil, true) {
		if incident.RuleID == "IS-004" {
			t.Fatal("known domain-controller replication was incorrectly flagged")
		}
	}
}

func TestTicketStringCannotSuppressUnapprovedOrForeignSourceChange(t *testing.T) {
	now := time.Now().UTC()
	snapshot := lab.Snapshot(now)
	events := lab.Scenario("benign-admin", "approved", now)
	for i := range events {
		events[i].Source = "unrelated-public-dataset"
	}
	found := false
	for _, incident := range detection.Detect(events, snapshot, nil, true) {
		if incident.RuleID == "IS-003" {
			found = true
			if len(incident.Findings) != 0 || incident.PolicyAware {
				t.Fatal("identities from unrelated sources were joined by account name")
			}
		}
	}
	if !found {
		t.Fatal("a ticket string suppressed a change outside the bound source")
	}
	events = lab.Scenario("benign-admin", "unapproved-group", now)
	events[0].Data["group"] = "Domain Admins"
	found = false
	for _, incident := range detection.Detect(events, snapshot, nil, true) {
		found = found || incident.RuleID == "IS-003"
	}
	if !found {
		t.Fatal("approval for a different group was incorrectly reused")
	}
}
