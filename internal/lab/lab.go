package lab

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strconv"
	"time"

	"github.com/YeandAmen/identityshield/internal/domain"
)

func Snapshot(now time.Time) domain.Snapshot {
	return domain.Snapshot{
		ID: "northstar-lab-v1", Organization: "Northstar Manufacturing", PolicyVersion: "RBAC-2026.01",
		CapturedAt: now.UTC(), Source: "synthetic-lab",
		EventSources: []string{"synthetic-lab"},
		Approvals:    []domain.Approval{{Ticket: "CHG-2048", Operator: "alex.rivera", Target: "alex.rivera", Group: "GG_IT_Administrators", ValidFrom: now.Add(-30 * 24 * time.Hour), ValidUntil: now.Add(24 * time.Hour)}},
		Users: []domain.User{
			{ID: "maya.chen", Name: "maya.chen", Role: "Helpdesk operator", Department: "IT support", Groups: []string{"gg-helpdesk"}, Enabled: true},
			{ID: "noah.williams", Name: "noah.williams", Role: "Finance employee", Department: "Finance", Groups: []string{"gg-finance"}, Enabled: true},
			{ID: "ava.patel", Name: "ava.patel", Role: "HR employee", Department: "People", Groups: []string{"gg-hr"}, Enabled: true},
			{ID: "leo.martin", Name: "leo.martin", Role: "OT engineer", Department: "Operations", Groups: []string{"gg-engineering"}, Enabled: true},
			{ID: "alex.rivera", Name: "alex.rivera", Role: "IT administrator", Department: "Infrastructure", Groups: []string{"gg-it-admin"}, Enabled: true},
			{ID: "svc.backup", Name: "svc.backup", Role: "Backup service", Department: "Infrastructure", Groups: []string{"gg-backup"}, Enabled: true},
		},
		Groups: []domain.Group{
			{ID: "gg-helpdesk", Name: "GG_Helpdesk", Members: []string{}},
			{ID: "gg-finance", Name: "GG_Finance", Members: []string{}},
			{ID: "gg-hr", Name: "GG_HR", Members: []string{}},
			{ID: "gg-engineering", Name: "GG_OT_Engineers", Members: []string{}},
			{ID: "gg-it-admin", Name: "GG_IT_Administrators", Members: []string{}},
			{ID: "gg-backup", Name: "GG_Backup", Members: []string{}},
			{ID: "dl-reset", Name: "DL_Staff_ResetPassword", Members: []string{"gg-helpdesk"}},
			{ID: "dl-engineering-admin", Name: "DL_Engineering_LocalAdmin", Members: []string{"gg-engineering", "gg-helpdesk"}},
			{ID: "dl-replication", Name: "DL_Directory_Replication", Members: []string{"gg-backup", "gg-it-admin"}},
			{ID: "dl-finance-rw", Name: "DL_Finance_ReadWrite", Members: []string{"gg-finance", "gg-helpdesk"}},
		},
		Assets: []domain.Asset{
			{ID: "ns-dc01", Name: "NS-DC01", Kind: "domain-controller", Zone: "IT", Critical: true},
			{ID: "ns-ws01", Name: "NS-WS01", Kind: "workstation", Zone: "IT"},
			{ID: "ns-fin01", Name: "NS-FIN01", Kind: "file-server", Zone: "IT", Critical: true},
			{ID: "ns-eng01", Name: "NS-ENG01", Kind: "engineering-workstation", Zone: "OT", Critical: true},
			{ID: "ns-plc01", Name: "NS-PLC01", Kind: "simulated-controller", Zone: "OT", Critical: true},
			{ID: "staff-ou", Name: "OU / Staff", Kind: "organizational-unit", Zone: "IT"},
		},
		Grants: []domain.Grant{
			{ID: "grant-reset", Principal: "dl-reset", Resource: "staff-ou", Right: "reset-password", Effect: "allow", Origin: "OU=Staff"},
			{ID: "grant-engineering-admin", Principal: "dl-engineering-admin", Resource: "ns-eng01", Right: "local-admin", Effect: "allow", Inherited: true, InheritedDepth: 1, Origin: "Engineering workstation policy"},
			{ID: "grant-replication", Principal: "dl-replication", Resource: "ns-dc01", Right: "replicate-directory", Effect: "allow", Origin: "Domain root"},
			{ID: "grant-finance-read", Principal: "dl-finance-rw", Resource: "ns-fin01", Right: "read", Effect: "allow"},
			{ID: "grant-finance-write", Principal: "dl-finance-rw", Resource: "ns-fin01", Right: "write", Effect: "allow"},
			{ID: "grant-it-admin", Principal: "gg-it-admin", Resource: "ns-ws01", Right: "local-admin", Effect: "allow"},
			{ID: "grant-ot-logon", Principal: "gg-engineering", Resource: "ns-eng01", Right: "remote-logon", Effect: "allow"},
		},
		Policies: []domain.Policy{
			{Role: "Helpdesk operator", Resource: "staff-ou", Rights: []string{"reset-password"}},
			{Role: "Helpdesk operator", Resource: "ns-ws01", Rights: []string{"remote-logon"}},
			{Role: "Finance employee", Resource: "ns-fin01", Rights: []string{"read", "write", "remote-logon"}},
			{Role: "HR employee", Resource: "ns-ws01", Rights: []string{"remote-logon"}},
			{Role: "OT engineer", Resource: "ns-eng01", Rights: []string{"remote-logon", "local-admin"}},
			{Role: "IT administrator", Resource: "ns-ws01", Rights: []string{"remote-logon", "local-admin"}},
			{Role: "IT administrator", Resource: "ns-dc01", Rights: []string{"replicate-directory"}},
			{Role: "Backup service", Resource: "ns-fin01", Rights: []string{"read"}},
		},
	}
}

func newEvent(run string, index int, timestamp time.Time, kind, actor, host, label string, data map[string]string) domain.Event {
	e := domain.Event{ID: fmt.Sprintf("LAB-%s-%04d", run, index), Timestamp: timestamp.UTC(), Kind: kind, Actor: actor, Host: host, SourceHost: "ns-ws01", Source: "synthetic-lab", DatasetID: "northstar-lab", RunID: run, Label: label, Data: data}
	if e.Data == nil {
		e.Data = map[string]string{}
	}
	e.Data["ground_truth_origin"] = "controlled synthetic scenario"
	raw, _ := json.Marshal(e)
	e.Raw = string(raw)
	hash := sha256.Sum256(raw)
	e.RawSHA256 = fmt.Sprintf("%x", hash)
	return e
}

// Baseline creates independently grouped runs with benign and attack-labelled
// authentication and tank telemetry. It is reproducible and visibly synthetic.
func Baseline(anchor time.Time) []domain.Event {
	rng := rand.New(rand.NewPCG(42, 2026))
	users := []string{"maya.chen", "noah.williams", "ava.patel", "alex.rivera", "svc.backup"}
	hosts := []string{"ns-ws01", "ns-fin01", "ns-ws01", "ns-ws01", "ns-fin01"}
	events := []domain.Event{}
	for run := 0; run < 90; run++ {
		start := anchor.Add(-time.Duration(90-run) * 150 * time.Minute).Truncate(5 * time.Minute)
		runID := fmt.Sprintf("baseline-%03d", run)
		actorIndex := run % len(users)
		attack := run%9 == 7
		failures := rng.IntN(4)
		count := 18 + rng.IntN(12)
		if attack {
			failures, count = 35+rng.IntN(25), 70+rng.IntN(20)
		}
		for n := 0; n < count; n++ {
			kind, label := "auth_success", "benign"
			if n < failures {
				kind = "auth_failure"
				if attack {
					label = "malicious"
				}
			}
			e := newEvent(runID, n, start.Add(time.Duration(n)*2*time.Second), kind, users[actorIndex], hosts[actorIndex], label, map[string]string{"logon_type": strconv.Itoa(2 + rng.IntN(2)), "event_id": "4624"})
			if kind == "auth_failure" {
				e.Data["event_id"] = "4625"
			}
			if attack {
				e.SourceHost = "lab-red01"
			}
			events = append(events, e)
		}
		for n := 0; n < 8; n++ {
			level, pressure, label := 52+rng.Float64()*6, 1.2+rng.Float64()*0.15, "benign"
			if attack && n > 3 {
				level, pressure, label = 97+rng.Float64()*3, 3+rng.Float64()*0.4, "malicious"
			}
			events = append(events, newEvent(runID+"-tank", n, start.Add(time.Duration(n)*15*time.Second), "ics_sample", "controller", "ns-plc01", label, map[string]string{"schema": "northstar-tank-v1", "mode": "running", "tank_level": fmt.Sprintf("%.3f", level), "pressure": fmt.Sprintf("%.3f", pressure), "flow_rate": fmt.Sprintf("%.3f", 2+rng.Float64()*0.3), "pump": "1"}))
		}
	}
	events = append(events, Scenario("identity-to-ot", "showcase-identity", anchor.Add(-14*time.Minute))...)
	events = append(events, Scenario("credential-access", "showcase-credentials", anchor.Add(-36*time.Minute))...)
	events = append(events, Scenario("benign-admin", "showcase-benign", anchor.Add(-65*time.Minute))...)
	events = append(events, Scenario("persistence", "showcase-persistence", anchor.Add(-100*time.Minute))...)
	for i := range events {
		events[i].Raw, events[i].RawSHA256 = "", ""
		raw, _ := json.Marshal(events[i])
		events[i].Raw = string(raw)
		hash := sha256.Sum256(raw)
		events[i].RawSHA256 = fmt.Sprintf("%x", hash)
	}
	return events
}

func Scenario(name, runID string, start time.Time) []domain.Event {
	start = start.UTC().Truncate(5 * time.Minute)
	events := []domain.Event{}
	add := func(kind, actor, host, label string, data map[string]string) *domain.Event {
		e := newEvent(runID, len(events), start.Add(time.Duration(len(events))*12*time.Second), kind, actor, host, label, data)
		events = append(events, e)
		return &events[len(events)-1]
	}
	switch name {
	case "identity-to-ot":
		e := add("group_change", "alex.rivera", "ns-dc01", "malicious", map[string]string{"group": "DL_Engineering_LocalAdmin", "action": "add", "event_id": "4732"})
		e.Target = "maya.chen"
		add("auth_success", "maya.chen", "ns-eng01", "malicious", map[string]string{"logon_type": "10", "event_id": "4624"})
		add("process", "maya.chen", "ns-eng01", "malicious", map[string]string{"command": "powershell.exe -EncodedCommand <synthetic-marker>", "event_id": "1"})
		add("ics_sample", "controller", "ns-plc01", "benign", map[string]string{"schema": "northstar-tank-v1", "mode": "running", "tank_level": "56.2", "pressure": "1.28", "flow_rate": "2.16", "pump": "1"})
		add("ics_sample", "controller", "ns-plc01", "malicious", map[string]string{"schema": "northstar-tank-v1", "mode": "running", "tank_level": "98.7", "pressure": "3.24", "flow_rate": "4.5", "pump": "1"})
	case "credential-access":
		add("acl_change", "alex.rivera", "ns-dc01", "malicious", map[string]string{"right": "replicate-directory", "principal": "svc.backup", "event_id": "5136"})
		add("directory_replication", "svc.backup", "ns-ws01", "malicious", map[string]string{"event_id": "4662", "object": "domain-root", "right": "replicate-directory"})
		add("process", "svc.backup", "ns-ws01", "malicious", map[string]string{"command": "rundll32.exe comsvcs.dll, MiniDump <synthetic-lsass-marker>", "event_id": "1"})
	case "persistence":
		add("service_created", "maya.chen", "ns-fin01", "malicious", map[string]string{"command": "cmd.exe /c <synthetic-service-marker>", "service": "LabUpdate", "event_id": "7045"})
		add("task_created", "maya.chen", "ns-fin01", "malicious", map[string]string{"command": "powershell.exe C:\\Temp\\lab-marker.ps1", "task": "LabMaintenance", "event_id": "4698"})
	case "password-spray":
		users := []string{"maya.chen", "noah.williams", "ava.patel", "leo.martin"}
		for n := 0; n < 16; n++ {
			e := add("auth_failure", users[n%len(users)], "ns-dc01", "malicious", map[string]string{"event_id": "4625", "logon_type": "3"})
			e.SourceHost = "lab-red01"
		}
	case "benign-admin":
		e := add("group_change", "alex.rivera", "ns-dc01", "benign", map[string]string{"group": "GG_IT_Administrators", "action": "add", "change_ticket": "CHG-2048", "event_id": "4728"})
		e.Target = "alex.rivera"
		add("process", "alex.rivera", "ns-ws01", "benign", map[string]string{"command": "powershell.exe -EncodedCommand <approved-deployment-marker>", "change_ticket": "CHG-2048", "event_id": "1"})
	}
	// Refresh raw provenance after scenario-specific fields have been assigned.
	for i := range events {
		events[i].Raw, events[i].RawSHA256 = "", ""
		raw, _ := json.Marshal(events[i])
		events[i].Raw = string(raw)
		hash := sha256.Sum256(raw)
		events[i].RawSHA256 = fmt.Sprintf("%x", hash)
	}
	return events
}

func ScenarioNames() []string {
	return []string{"identity-to-ot", "credential-access", "password-spray", "persistence", "benign-admin"}
}
