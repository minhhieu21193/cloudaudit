package checks

import (
	"encoding/json"
	"testing"
	"time"
)

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		in      string
		want    Severity
		wantErr bool
	}{
		{"low", SeverityLow, false},
		{"MEDIUM", SeverityMedium, false},
		{"High", SeverityHigh, false},
		{"critical", SeverityCritical, false},
		{"urgent", 0, true},
		{"", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseSeverity(tt.in)
		if (err != nil) != tt.wantErr {
			t.Fatalf("ParseSeverity(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
		}
		if got != tt.want {
			t.Errorf("ParseSeverity(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestSeverityOrdering(t *testing.T) {
	ordered := []Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for i := 1; i < len(ordered); i++ {
		if ordered[i-1] >= ordered[i] {
			t.Fatalf("%v must rank below %v", ordered[i-1], ordered[i])
		}
	}
}

func TestSeverityJSONRoundTrip(t *testing.T) {
	in := Finding{CheckID: "x", Severity: SeverityHigh}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Finding
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Severity != SeverityHigh {
		t.Fatalf("round trip severity = %v, want HIGH (json %s)", out.Severity, b)
	}
	if _, err := json.Marshal(Finding{Severity: 0}); err == nil {
		t.Fatal("expected error marshalling an unset severity")
	}
}

func TestNewFindingAndDaysSince(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	env := &Env{Region: "ap-northeast-1", Now: now}
	m := Meta{ID: "demo", Category: CategoryCost, DocsURL: "https://example.com"}
	f := m.NewFinding(env, "vol-1")
	if f.CheckID != "demo" || f.Region != "ap-northeast-1" || f.ResourceID != "vol-1" || f.Category != CategoryCost || f.DocsURL == "" {
		t.Fatalf("unexpected finding %+v", f)
	}
	if got := env.DaysSince(now.Add(-91 * 24 * time.Hour)); got != 91 {
		t.Fatalf("DaysSince = %d, want 91", got)
	}
}
