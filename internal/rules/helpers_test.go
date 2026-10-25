package rules

import (
	"math"
	"testing"
	"time"

	"github.com/minhhieu21193/cloudaudit/internal/checks"
)

var testNow = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func testEnv(region string) *checks.Env {
	return &checks.Env{
		Region:    region,
		AccountID: "123456789012",
		Now:       testNow,
		Config:    checks.DefaultConfig(),
	}
}

func daysAgo(n int) time.Time { return testNow.Add(-time.Duration(n) * 24 * time.Hour) }

func approxUSD(t *testing.T, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 0.005 {
		t.Errorf("EstMonthlyUSD = %.4f, want %.4f", got, want)
	}
}

// byResource indexes findings by resource ID and fails on duplicates.
func byResource(t *testing.T, fs []checks.Finding) map[string]checks.Finding {
	t.Helper()
	m := make(map[string]checks.Finding, len(fs))
	for _, f := range fs {
		if _, dup := m[f.ResourceID]; dup {
			t.Fatalf("duplicate finding for %s", f.ResourceID)
		}
		m[f.ResourceID] = f
	}
	return m
}

func TestAllChecksHaveUniqueIDsAndMeta(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range All() {
		m := c.Meta()
		if m.ID == "" || m.Name == "" || m.DocsURL == "" {
			t.Errorf("check %T has incomplete meta %+v", c, m)
		}
		if m.Category != checks.CategoryCost && m.Category != checks.CategorySecurity {
			t.Errorf("check %s has invalid category %q", m.ID, m.Category)
		}
		if seen[m.ID] {
			t.Errorf("duplicate check ID %s", m.ID)
		}
		seen[m.ID] = true
	}
}

func TestCostSeverity(t *testing.T) {
	cases := map[float64]checks.Severity{0: checks.SeverityLow, 19.99: checks.SeverityLow, 20: checks.SeverityMedium, 100: checks.SeverityHigh}
	for usd, want := range cases {
		if got := costSeverity(usd); got != want {
			t.Errorf("costSeverity(%v) = %v, want %v", usd, got, want)
		}
	}
}
