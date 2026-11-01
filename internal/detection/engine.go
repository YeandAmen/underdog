package detection

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/YeandAmen/identityshield/internal/domain"
	"github.com/YeandAmen/identityshield/internal/identity"
)

func Rules() []domain.Rule {
	return []domain.Rule{
		{ID: "IS-001", Name: "Password spraying", Description: "Eight or more failures against at least three users from the same source in five minutes.", Severity: "high", Technique: "T1110.003", LogSource: "Authentication", FalsePositives: "SSO outages and misconfigured authentication gateways.", Enabled: true},
		{ID: "IS-002", Name: "Repeated account authentication failures", Description: "At least twelve failures for one account in a five-minute window.", Severity: "medium", Technique: "T1110.001", LogSource: "Authentication", FalsePositives: "Expired service credentials, lockout troubleshooting, and abandoned clients.", Enabled: true},
		{ID: "IS-003", Name: "Privileged group membership change", Description: "An account is added to a sensitive administrator group.", Severity: "high", Technique: "T1098", LogSource: "Windows Security", FalsePositives: "Approved provisioning. Tuning requires a bound source and an independent approval matching the operator, target, group, ticket, and time window.", Enabled: true},
		{ID: "IS-004", Name: "Directory replication from a non-controller", Description: "Replication rights are exercised on a host not identified as a domain controller.", Severity: "critical", Technique: "T1003.006", LogSource: "AD directory auditing", FalsePositives: "Approved identity sync agents; inventory and validate them explicitly.", Enabled: true},
		{ID: "IS-005", Name: "LSASS memory dump behaviour", Description: "A process command combines LSASS with a memory-dump mechanism.", Severity: "critical", Technique: "T1003.001", LogSource: "Sysmon / process creation", FalsePositives: "Diagnostic memory collection; corroborate the process, operator, and destination.", Enabled: true},
		{ID: "IS-006", Name: "Encoded PowerShell execution", Description: "PowerShell executes an encoded command.", Severity: "medium", Technique: "T1059.001", LogSource: "Sysmon / PowerShell", FalsePositives: "Management software and deployment scripts may use encoded commands.", Enabled: true},
		{ID: "IS-007", Name: "Remote service with script execution", Description: "A remote service executes a shell or script interpreter.", Severity: "high", Technique: "T1021.002", LogSource: "Service auditing", FalsePositives: "Remote administration tools and approved software deployment.", Enabled: true},
		{ID: "IS-008", Name: "Suspicious scheduled task", Description: "A task executes a shell or a payload from a temporary location.", Severity: "high", Technique: "T1053.005", LogSource: "Windows Security / task scheduler", FalsePositives: "Updaters and administrative scheduled tasks.", Enabled: true},
		{ID: "IS-009", Name: "Security log cleared", Description: "An explicit log-clear event is observed.", Severity: "high", Technique: "T1070.001", LogSource: "Windows Security", FalsePositives: "Lab resets or documented retention changes; preserve preceding evidence.", Enabled: true},
		{ID: "IS-010", Name: "Sensitive directory permission change", Description: "A change grants replication, group-write, or broad control rights.", Severity: "critical", Technique: "T1098", LogSource: "AD change auditing", FalsePositives: "Planned delegation changes; compare against the approved role policy.", Enabled: true},
		{ID: "IS-011", Name: "Unexpected access to an OT engineering host", Description: "An observed, known user logs on to an OT host outside their approved role scope.", Severity: "high", Technique: "T1021.001", LogSource: "Authentication + asset policy", FalsePositives: "A stale access policy or documented temporary engineering access.", Enabled: true},
		{ID: "IS-012", Name: "Industrial process outside its declared envelope", Description: "The simulated tank exceeds its explicitly configured level or pressure envelope.", Severity: "high", Technique: "T0831", LogSource: "Normalized ICS telemetry", FalsePositives: "Maintenance modes and sensor faults. This rule does not assume HAI tag units.", Enabled: true},
	}
}

type bucket struct {
	Rule   domain.Rule
	Events []domain.Event
}

func Detect(events []domain.Event, snapshot domain.Snapshot, enabled map[string]bool, policyAware bool) []domain.Incident {
	ordered := append([]domain.Event{}, events...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Timestamp.Before(ordered[j].Timestamp) })
	events = ordered
	rules := Rules()
	byID := map[string]domain.Rule{}
	for _, r := range rules {
		if active, exists := enabled[r.ID]; exists {
			r.Enabled = active
		}
		byID[r.ID] = r
	}
	buckets := map[string]*bucket{}
	add := func(id, group string, event domain.Event) {
		rule := byID[id]
		if !rule.Enabled {
			return
		}
		slot := event.Timestamp.UTC().Truncate(5 * time.Minute).Format(time.RFC3339)
		key := id + "|" + event.Source + "|" + event.RunID + "|" + group + "|" + slot
		if buckets[key] == nil {
			buckets[key] = &bucket{Rule: rule}
		}
		buckets[key].Events = append(buckets[key].Events, event)
	}
	assets := map[string]domain.Asset{}
	for _, a := range snapshot.Assets {
		assets[strings.ToLower(a.ID)] = a
		assets[strings.ToLower(a.Name)] = a
		if a.Address != "" {
			assets[strings.ToLower(a.Address)] = a
		}
	}
	sessions := map[string]domain.Event{}
	for _, event := range events {
		if event.Kind == "auth_success" && event.Data["target_logon_id"] != "" && event.SourceHost != "" {
			sessions[strings.ToLower(event.Host)+"|"+event.Data["target_logon_id"]] = event
		}
		command := strings.ToLower(event.Data["command"])
		if event.Kind == "auth_failure" {
			src := event.SourceHost
			if src == "" {
				src = event.Host
			}
			add("IS-001", src, event)
			add("IS-002", event.Actor, event)
		}
		if event.Kind == "group_change" && event.Data["action"] != "remove" {
			group := strings.ToLower(event.Data["group"])
			if strings.Contains(group, "admin") || strings.Contains(group, "engineer") {
				suppress := false
				if policyAware {
					suppress = identity.ApprovedChange(snapshot, event)
				}
				if !suppress {
					add("IS-003", event.Target, event)
				}
			}
		}
		if event.Kind == "directory_replication" {
			client := event.SourceHost
			if client == "" {
				if session, exists := sessions[strings.ToLower(event.Host)+"|"+event.Data["subject_logon_id"]]; exists && event.Timestamp.Sub(session.Timestamp) <= 24*time.Hour {
					client = session.SourceHost
				}
			}
			if client == "" && assets[strings.ToLower(event.Host)].Kind != "" && assets[strings.ToLower(event.Host)].Kind != "domain-controller" {
				client = event.Host
			}
			if client != "" && assets[strings.ToLower(client)].Kind != "domain-controller" {
				add("IS-004", event.Actor, event)
			}
		}
		if event.Kind == "process" && strings.Contains(command, "lsass") && (strings.Contains(command, "minidump") || strings.Contains(command, "comsvcs") || strings.Contains(command, "procdump")) {
			add("IS-005", event.Actor, event)
		}
		if event.Kind == "process_access" && strings.HasSuffix(strings.ToLower(event.Data["target_image"]), "\\lsass.exe") && (strings.Contains(strings.ToLower(event.Data["call_trace"]), "comsvcs") || strings.Contains(strings.ToLower(event.Data["source_image"]), "procdump")) {
			add("IS-005", event.Actor, event)
		}
		if event.Kind == "process" && (strings.Contains(command, "powershell") || strings.Contains(command, "pwsh")) && (strings.Contains(command, "-encodedcommand") || strings.Contains(command, " -enc ")) {
			add("IS-006", event.Actor, event)
		}
		if event.Kind == "service_created" && event.SourceHost != "" && !strings.EqualFold(event.SourceHost, event.Host) && (strings.Contains(command, "powershell") || strings.Contains(command, "cmd.exe") || strings.Contains(command, "wscript")) {
			add("IS-007", event.Actor, event)
		}
		if event.Kind == "task_created" && (strings.Contains(command, "powershell") || strings.Contains(command, "\\temp\\") || strings.Contains(command, "/tmp/")) {
			add("IS-008", event.Actor, event)
		}
		if event.Kind == "log_cleared" {
			add("IS-009", event.Actor, event)
		}
		if event.Kind == "acl_change" && (event.Data["right"] == "replicate-directory" || event.Data["right"] == "write-members" || strings.Contains(strings.ToLower(event.Data["right"]), "genericall")) {
			add("IS-010", event.Actor, event)
		}
		if identity.ContextApplies(snapshot, event.Source) && event.Kind == "auth_success" && assets[strings.ToLower(event.Host)].Zone == "OT" {
			if user, known := identity.FindUser(snapshot, event.Actor); known && !identity.Allowed(snapshot, user.Role, assets[strings.ToLower(event.Host)].ID, "remote-logon") {
				add("IS-011", event.Actor, event)
			}
		}
		if event.Kind == "ics_sample" && event.Data["schema"] == "northstar-tank-v1" && event.Data["mode"] == "running" {
			level, lerr := strconv.ParseFloat(event.Data["tank_level"], 64)
			pressure, perr := strconv.ParseFloat(event.Data["pressure"], 64)
			if (lerr == nil && (level < 0 || level > 95)) || (perr == nil && pressure > 2.8) {
				add("IS-012", event.Host, event)
			}
		}
	}
	findings := identity.Audit(snapshot)
	out := []domain.Incident{}
	for key, b := range buckets {
		if b.Rule.ID == "IS-001" {
			users := map[string]bool{}
			for _, e := range b.Events {
				users[e.Actor] = true
			}
			if len(b.Events) < 8 || len(users) < 3 {
				continue
			}
		}
		if b.Rule.ID == "IS-002" && len(b.Events) < 12 {
			continue
		}
		sort.Slice(b.Events, func(i, j int) bool {
			if b.Events[i].Timestamp.Equal(b.Events[j].Timestamp) {
				return b.Events[i].ID < b.Events[j].ID
			}
			return b.Events[i].Timestamp.Before(b.Events[j].Timestamp)
		})
		hash := sha256.Sum256([]byte(key))
		first := b.Events[0]
		inc := domain.Incident{
			ID: fmt.Sprintf("CASE-%x", hash[:4]), Title: b.Rule.Name, RuleID: b.Rule.ID,
			Technique: b.Rule.Technique, Severity: b.Rule.Severity, Priority: domain.SeverityPriority(b.Rule.Severity),
			Actor: first.Actor, Host: first.Host, StartedAt: first.Timestamp,
			LastSeen: b.Events[len(b.Events)-1].Timestamp, Status: "open", GroundTruth: "unknown",
			TimeBasis: first.Data["time_basis"],
			EventIDs:  []string{}, Findings: []domain.Finding{}, Context: []string{}, PolicyAware: policyAware,
		}
		inc.Summary = fmt.Sprintf("%s %d supporting event(s) were observed on %s.", b.Rule.Description, len(b.Events), first.Host)
		allBenign, anyMalicious := true, false
		actors := map[string]bool{}
		for _, e := range b.Events {
			inc.EventIDs = append(inc.EventIDs, e.ID)
			allBenign = allBenign && e.Label == "benign"
			anyMalicious = anyMalicious || e.Label == "malicious"
			actors[e.Actor], actors[e.Target] = true, true
		}
		if anyMalicious {
			inc.GroundTruth = "malicious"
		} else if allBenign {
			inc.GroundTruth = "benign"
		}
		if policyAware && identity.ContextApplies(snapshot, first.Source) {
			for _, finding := range findings {
				matched := false
				for actor := range actors {
					user, ok := identity.FindUser(snapshot, actor)
					if ok && user.ID == finding.UserID {
						matched = true
					}
				}
				if matched {
					inc.Findings = append(inc.Findings, finding)
				}
			}
			if len(inc.Findings) > 0 {
				inc.Priority = min(99, inc.Priority+4)
				inc.Context = append(inc.Context, fmt.Sprintf("%d permission discrepancy/discrepancies affect a principal in this evidence bundle.", len(inc.Findings)))
			}
			if user, ok := identity.FindUser(snapshot, first.Actor); ok {
				inc.Context = append(inc.Context, "Approved role: "+user.Role+" · policy "+snapshot.PolicyVersion)
			}
		} else {
			inc.PolicyAware = false
			inc.Context = append(inc.Context, "No approved identity-policy binding exists for this event source; matching account names from another dataset are not treated as the same identity.")
		}
		evidenceDigest := sha256.Sum256([]byte(strings.Join(inc.EventIDs, "|") + "|" + snapshot.PolicyVersion + "|" + snapshot.ID))
		inc.EvidenceHash = fmt.Sprintf("%x", evidenceDigest)
		out = append(out, inc)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		if out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].ID < out[j].ID
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}
