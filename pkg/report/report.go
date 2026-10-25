// Package report turns a scan result into Markdown, self-contained HTML or
// JSON. All USD figures are estimates from a static price table and are
// labelled as such in every format.
package report

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/minhhieu21193/cloudaudit/internal/checks"
	"github.com/minhhieu21193/cloudaudit/internal/scan"
)

type Format string

const (
	FormatMarkdown Format = "md"
	FormatHTML     Format = "html"
	FormatJSON     Format = "json"
)

func ParseFormat(s string) (Format, error) {
	switch f := Format(strings.ToLower(s)); f {
	case FormatMarkdown, FormatHTML, FormatJSON:
		return f, nil
	case "markdown":
		return FormatMarkdown, nil
	}
	return "", fmt.Errorf("unknown format %q (want md, html or json)", s)
}

type Options struct {
	Version     string
	Demo        bool
	MinSeverity checks.Severity
}

// SeverityCount is one row of the summary table.
type SeverityCount struct {
	Severity checks.Severity `json:"severity"`
	Count    int             `json:"count"`
}

type CheckInfo struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Category checks.Category `json:"category"`
	Global   bool            `json:"global"`
	Findings int             `json:"findings"`
	Errors   int             `json:"errors"`
}

type Report struct {
	Tool            string           `json:"tool"`
	Version         string           `json:"version"`
	Demo            bool             `json:"demo"`
	AccountID       string           `json:"account_id,omitempty"`
	GeneratedAt     time.Time        `json:"generated_at"`
	DurationSeconds float64          `json:"duration_seconds"`
	MinSeverity     checks.Severity  `json:"min_severity"`
	Regions         []string         `json:"regions"`
	Checks          []CheckInfo      `json:"checks"`
	Summary         Summary          `json:"summary"`
	Cost            []checks.Finding `json:"cost_findings"`
	Security        []checks.Finding `json:"security_findings"`
	Errors          []scan.Error     `json:"errors"`
}

type Summary struct {
	BySeverity []SeverityCount `json:"by_severity"`
	Total      int             `json:"total_findings"`
	// EstMonthlyWasteUSD is the sum of cost findings shown in the report.
	EstMonthlyWasteUSD float64 `json:"est_monthly_waste_usd"`
	// Hidden counts findings below MinSeverity that were left out.
	Hidden int `json:"hidden_below_min_severity"`
}

var severitiesDesc = []checks.Severity{checks.SeverityCritical, checks.SeverityHigh, checks.SeverityMedium, checks.SeverityLow}

// Build assembles a report. metas describes the checks that ran, in display
// order.
func Build(res scan.Result, metas []checks.Meta, opts Options) Report {
	minSev := opts.MinSeverity
	if minSev == 0 {
		minSev = checks.SeverityLow
	}
	r := Report{
		Tool:            "cloudaudit",
		Version:         opts.Version,
		Demo:            opts.Demo,
		AccountID:       res.AccountID,
		GeneratedAt:     res.StartedAt.UTC(),
		DurationSeconds: res.Duration.Seconds(),
		MinSeverity:     minSev,
		Regions:         slices.Clone(res.Regions),
		Cost:            []checks.Finding{},
		Security:        []checks.Finding{},
		Errors:          slices.Clone(res.Errors),
	}
	if r.Errors == nil {
		r.Errors = []scan.Error{}
	}

	counts := map[checks.Severity]int{}
	perCheck := map[string]int{}
	for _, f := range res.Findings {
		if f.Severity < minSev {
			r.Summary.Hidden++
			continue
		}
		counts[f.Severity]++
		perCheck[f.CheckID]++
		if f.Category == checks.CategoryCost {
			r.Cost = append(r.Cost, f)
			r.Summary.EstMonthlyWasteUSD += f.EstMonthlyUSD
		} else {
			r.Security = append(r.Security, f)
		}
	}
	r.Summary.Total = len(r.Cost) + len(r.Security)
	for _, s := range severitiesDesc {
		r.Summary.BySeverity = append(r.Summary.BySeverity, SeverityCount{Severity: s, Count: counts[s]})
	}

	errsPerCheck := map[string]int{}
	for _, e := range res.Errors {
		errsPerCheck[e.CheckID]++
	}
	for _, m := range metas {
		r.Checks = append(r.Checks, CheckInfo{ID: m.ID, Name: m.Name, Category: m.Category, Global: m.Global, Findings: perCheck[m.ID], Errors: errsPerCheck[m.ID]})
	}

	slices.SortStableFunc(r.Cost, func(a, b checks.Finding) int {
		return cmp.Or(cmp.Compare(b.EstMonthlyUSD, a.EstMonthlyUSD), cmp.Compare(b.Severity, a.Severity), tiebreak(a, b))
	})
	slices.SortStableFunc(r.Security, func(a, b checks.Finding) int {
		return cmp.Or(cmp.Compare(b.Severity, a.Severity), tiebreak(a, b))
	})
	return r
}

func tiebreak(a, b checks.Finding) int {
	return cmp.Or(cmp.Compare(a.CheckID, b.CheckID), cmp.Compare(a.Region, b.Region), cmp.Compare(a.ResourceID, b.ResourceID))
}

// MaxSeverity returns the highest severity in the report, or 0 if empty.
func (r Report) MaxSeverity() checks.Severity {
	for _, c := range r.Summary.BySeverity {
		if c.Count > 0 {
			return c.Severity
		}
	}
	return 0
}

func Write(w io.Writer, format Format, r Report) error {
	switch format {
	case FormatMarkdown:
		return WriteMarkdown(w, r)
	case FormatHTML:
		return WriteHTML(w, r)
	case FormatJSON:
		return WriteJSON(w, r)
	}
	return fmt.Errorf("unknown format %q", format)
}

func WriteJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// usd formats an estimate as "$1,234.56".
func usd(v float64) string {
	s := fmt.Sprintf("%.2f", v)
	whole, frac, _ := strings.Cut(s, ".")
	neg := strings.HasPrefix(whole, "-")
	whole = strings.TrimPrefix(whole, "-")
	var b strings.Builder
	for i, ch := range whole {
		if i > 0 && (len(whole)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(ch)
	}
	out := "$" + b.String() + "." + frac
	if neg {
		out = "-" + out
	}
	return out
}
