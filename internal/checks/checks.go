// Package checks defines the audit model shared by every rule, the scanner
// and the report writers.
package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
)

// GlobalRegion is the Region value for findings from account-wide services
// (IAM, S3 account settings, CloudTrail).
const GlobalRegion = "global"

type Category string

const (
	CategoryCost     Category = "cost"
	CategorySecurity Category = "security"
)

type Severity int

const (
	SeverityLow Severity = iota + 1
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityLow:      "LOW",
	SeverityMedium:   "MEDIUM",
	SeverityHigh:     "HIGH",
	SeverityCritical: "CRITICAL",
}

func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return fmt.Sprintf("Severity(%d)", int(s))
}

func (s Severity) MarshalText() ([]byte, error) {
	if _, ok := severityNames[s]; !ok {
		return nil, fmt.Errorf("invalid severity %d", int(s))
	}
	return []byte(s.String()), nil
}

func (s *Severity) UnmarshalText(text []byte) error {
	parsed, err := ParseSeverity(string(text))
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// ParseSeverity accepts severity names case-insensitively.
func ParseSeverity(s string) (Severity, error) {
	for sev, name := range severityNames {
		if strings.EqualFold(s, name) {
			return sev, nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q (want LOW, MEDIUM, HIGH or CRITICAL)", s)
}

// Finding is one issue on one resource.
type Finding struct {
	CheckID    string   `json:"check_id"`
	Category   Category `json:"category"`
	Region     string   `json:"region"`
	ResourceID string   `json:"resource_id"`
	Title      string   `json:"title"`
	Severity   Severity `json:"severity"`
	// EstMonthlyUSD is an estimate from the static price table; always 0 for
	// security findings.
	EstMonthlyUSD  float64 `json:"est_monthly_usd"`
	Evidence       string  `json:"evidence"`
	Recommendation string  `json:"recommendation"`
	// FixCommand is printed for a human to review and run; cloudaudit never
	// executes it.
	FixCommand string `json:"fix_command,omitempty"`
	DocsURL    string `json:"docs_url,omitempty"`
}

// Meta describes a check independently of any scan.
type Meta struct {
	ID       string
	Name     string
	Category Category
	// Global checks run once per scan instead of once per region.
	Global  bool
	DocsURL string
}

// NewFinding returns a Finding pre-filled with the check's identity and the
// region from env.
func (m Meta) NewFinding(env *Env, resourceID string) Finding {
	return Finding{
		CheckID:    m.ID,
		Category:   m.Category,
		Region:     env.Region,
		ResourceID: resourceID,
		DocsURL:    m.DocsURL,
	}
}

type Check interface {
	Meta() Meta
	Run(ctx context.Context, env *Env) ([]Finding, error)
}

// Config holds the tunable thresholds used by the rules.
type Config struct {
	SnapshotMinAgeDays  int
	StoppedMinDays      int
	AccessKeyMaxAgeDays int
	IdleLookbackDays    int
}

func DefaultConfig() Config {
	return Config{
		SnapshotMinAgeDays:  90,
		StoppedMinDays:      30,
		AccessKeyMaxAgeDays: 90,
		IdleLookbackDays:    14,
	}
}

// Env is everything a check needs to run in one region (or globally).
type Env struct {
	Region    string
	AccountID string
	Now       time.Time
	Config    Config
	Clients   awsapi.Clients
}

// DaysSince returns whole days elapsed between t and env.Now.
func (e *Env) DaysSince(t time.Time) int {
	return int(e.Now.Sub(t).Hours() / 24)
}
