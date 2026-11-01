package domain

import "time"

type Event struct {
	ID         string            `json:"id"`
	Timestamp  time.Time         `json:"timestamp"`
	Kind       string            `json:"kind"`
	Actor      string            `json:"actor"`
	Host       string            `json:"host"`
	SourceHost string            `json:"source_host,omitempty"`
	Target     string            `json:"target,omitempty"`
	Source     string            `json:"source"`
	DatasetID  string            `json:"dataset_id"`
	RunID      string            `json:"run_id,omitempty"`
	Label      string            `json:"label"`
	Data       map[string]string `json:"data"`
	Raw        string            `json:"raw,omitempty"`
	RawSHA256  string            `json:"raw_sha256,omitempty"`
}

type User struct {
	ID         string   `json:"id"`
	SID        string   `json:"sid,omitempty"`
	Name       string   `json:"name"`
	Role       string   `json:"role"`
	Department string   `json:"department"`
	Groups     []string `json:"groups"`
	Enabled    bool     `json:"enabled"`
}

type Group struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Members []string `json:"members"`
}

type Asset struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Address  string `json:"address,omitempty"`
	Kind     string `json:"kind"`
	Zone     string `json:"zone"`
	Critical bool   `json:"critical"`
}

// Grant is a normalized, single-action permission, not an arbitrary Windows ACE.
// Collectors must resolve object scope before emitting a grant. For one action,
// canonical precedence is explicit deny, explicit allow, then inherited ACEs
// ordered by their distance from the object (deny before allow at each distance).
type Grant struct {
	ID             string `json:"id"`
	Principal      string `json:"principal"`
	Resource       string `json:"resource"`
	Right          string `json:"right"`
	Effect         string `json:"effect"`
	Inherited      bool   `json:"inherited"`
	InheritedDepth int    `json:"inherited_depth,omitempty"`
	Origin         string `json:"origin,omitempty"`
}

type Policy struct {
	Role     string   `json:"role"`
	Resource string   `json:"resource"`
	Rights   []string `json:"rights"`
}

type Snapshot struct {
	ID            string     `json:"id"`
	Organization  string     `json:"organization"`
	PolicyVersion string     `json:"policy_version"`
	CapturedAt    time.Time  `json:"captured_at"`
	Source        string     `json:"source"`
	EventSources  []string   `json:"event_sources,omitempty"`
	Users         []User     `json:"users"`
	Groups        []Group    `json:"groups"`
	Assets        []Asset    `json:"assets"`
	Grants        []Grant    `json:"grants"`
	Policies      []Policy   `json:"policies"`
	Approvals     []Approval `json:"approvals,omitempty"`
}

type Approval struct {
	Ticket     string    `json:"ticket"`
	Operator   string    `json:"operator"`
	Target     string    `json:"target"`
	Group      string    `json:"group"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidUntil time.Time `json:"valid_until"`
}

type Finding struct {
	ID        string   `json:"id"`
	UserID    string   `json:"user_id"`
	UserName  string   `json:"user_name"`
	Role      string   `json:"role"`
	Resource  string   `json:"resource"`
	AssetName string   `json:"asset_name"`
	Right     string   `json:"right"`
	Severity  string   `json:"severity"`
	Path      []string `json:"path"`
	GrantID   string   `json:"grant_id"`
	Reason    string   `json:"reason"`
	Fix       string   `json:"fix"`
}

type Rule struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	Severity       string `json:"severity"`
	Technique      string `json:"technique"`
	LogSource      string `json:"log_source"`
	FalsePositives string `json:"false_positives"`
	Enabled        bool   `json:"enabled"`
	Matches        int    `json:"matches"`
}

type Incident struct {
	ID           string    `json:"id"`
	Title        string    `json:"title"`
	Summary      string    `json:"summary"`
	RuleID       string    `json:"rule_id"`
	Technique    string    `json:"technique"`
	Severity     string    `json:"severity"`
	Priority     int       `json:"priority"`
	Actor        string    `json:"actor"`
	Host         string    `json:"host"`
	StartedAt    time.Time `json:"started_at"`
	LastSeen     time.Time `json:"last_seen"`
	TimeBasis    string    `json:"time_basis,omitempty"`
	Status       string    `json:"status"`
	GroundTruth  string    `json:"ground_truth"`
	EventIDs     []string  `json:"event_ids"`
	Findings     []Finding `json:"findings"`
	PolicyAware  bool      `json:"policy_aware"`
	Context      []string  `json:"context"`
	EvidenceHash string    `json:"evidence_hash"`
}

type Claim struct {
	Text        string   `json:"text"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type Report struct {
	IncidentID   string    `json:"incident_id"`
	Summary      string    `json:"summary"`
	Verdict      string    `json:"verdict"`
	Claims       []Claim   `json:"claims"`
	NextSteps    []string  `json:"next_steps"`
	Limitations  []string  `json:"limitations"`
	Provider     string    `json:"provider"`
	Model        string    `json:"model"`
	GeneratedAt  time.Time `json:"generated_at"`
	EvidenceHash string    `json:"evidence_hash"`
}

type Review struct {
	IncidentID string    `json:"incident_id"`
	Verdict    string    `json:"verdict"`
	Reason     string    `json:"reason"`
	Reviewer   string    `json:"reviewer"`
	ReviewedAt time.Time `json:"reviewed_at"`
}

type Dataset struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Source         string    `json:"source"`
	Format         string    `json:"format"`
	ImportedAt     time.Time `json:"imported_at"`
	EventCount     int       `json:"event_count"`
	BenignCount    int       `json:"benign_count"`
	MaliciousCount int       `json:"malicious_count"`
	UnknownCount   int       `json:"unknown_count"`
	SHA256         string    `json:"sha256"`
	SourceURL      string    `json:"source_url,omitempty"`
	License        string    `json:"license"`
	Synthetic      bool      `json:"synthetic"`
	Notes          string    `json:"notes"`
}

type CatalogEntry struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Format      string `json:"format"`
	License     string `json:"license"`
	SourceURL   string `json:"source_url"`
	Access      string `json:"access"`
	Notes       string `json:"notes"`
	DownloadURL string `json:"-"`
	CanFetch    bool   `json:"can_fetch"`
	KaggleSlug  string `json:"kaggle_slug,omitempty"`
}

func ValidLabel(s string) bool { return s == "benign" || s == "malicious" || s == "unknown" }

func SeverityPriority(s string) int {
	switch s {
	case "critical":
		return 94
	case "high":
		return 78
	case "medium":
		return 54
	default:
		return 28
	}
}
