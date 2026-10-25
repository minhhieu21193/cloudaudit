package report

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/minhhieu21193/cloudaudit/internal/checks"
	"github.com/minhhieu21193/cloudaudit/internal/scan"
)

func sampleResult() (scan.Result, []checks.Meta) {
	res := scan.Result{
		AccountID: "123456789012",
		StartedAt: time.Date(2026, 10, 25, 9, 30, 0, 0, time.UTC),
		Duration:  1500 * time.Millisecond,
		Regions:   []string{"ap-northeast-1", "ap-southeast-1"},
		Findings: []checks.Finding{
			{CheckID: "ebs-unattached", Category: checks.CategoryCost, Region: "ap-northeast-1", ResourceID: "vol-small", Title: "small", Severity: checks.SeverityLow, EstMonthlyUSD: 4.8},
			{CheckID: "nat-idle", Category: checks.CategoryCost, Region: "ap-northeast-1", ResourceID: "nat-1", Title: "nat", Severity: checks.SeverityMedium, EstMonthlyUSD: 45.26, FixCommand: "aws ec2 delete-nat-gateway --nat-gateway-id nat-1"},
			{CheckID: "ec2-stopped", Category: checks.CategoryCost, Region: "ap-southeast-1", ResourceID: "i-1", Title: "big", Severity: checks.SeverityHigh, EstMonthlyUSD: 1234.5},
			{CheckID: "ebs-encryption-default", Category: checks.CategorySecurity, Region: "ap-southeast-1", ResourceID: "ebs-encryption-by-default", Title: "enc", Severity: checks.SeverityMedium},
			{CheckID: "root-account", Category: checks.CategorySecurity, Region: "global", ResourceID: "root/mfa", Title: "root <b>mfa</b> | pipe", Severity: checks.SeverityCritical},
			{CheckID: "sg-open-admin-ports", Category: checks.CategorySecurity, Region: "ap-northeast-1", ResourceID: "sg-1", Title: "sg", Severity: checks.SeverityHigh},
		},
		Errors: []scan.Error{{Region: "ap-southeast-1", CheckID: "nat-idle", Message: "AccessDenied: cloudwatch:GetMetricStatistics"}},
	}
	metas := []checks.Meta{
		{ID: "ebs-unattached", Name: "Unattached EBS volumes", Category: checks.CategoryCost},
		{ID: "nat-idle", Name: "Idle NAT Gateways", Category: checks.CategoryCost},
		{ID: "root-account", Name: "Root", Category: checks.CategorySecurity, Global: true},
	}
	return res, metas
}

func TestBuildSortsAndTotals(t *testing.T) {
	res, metas := sampleResult()
	r := Build(res, metas, Options{Version: "v1.2.3"})

	var costOrder []string
	for _, f := range r.Cost {
		costOrder = append(costOrder, f.ResourceID)
	}
	if strings.Join(costOrder, ",") != "i-1,nat-1,vol-small" {
		t.Errorf("cost order = %v, want by USD desc", costOrder)
	}
	var secOrder []string
	for _, f := range r.Security {
		secOrder = append(secOrder, f.Severity.String())
	}
	if strings.Join(secOrder, ",") != "CRITICAL,HIGH,MEDIUM" {
		t.Errorf("security order = %v, want by severity desc", secOrder)
	}
	if math.Abs(r.Summary.EstMonthlyWasteUSD-1284.56) > 1e-9 {
		t.Errorf("waste = %v", r.Summary.EstMonthlyWasteUSD)
	}
	if r.Summary.Total != 6 || r.MaxSeverity() != checks.SeverityCritical {
		t.Errorf("total = %d, max = %v", r.Summary.Total, r.MaxSeverity())
	}
	want := map[checks.Severity]int{checks.SeverityCritical: 1, checks.SeverityHigh: 2, checks.SeverityMedium: 2, checks.SeverityLow: 1}
	for _, c := range r.Summary.BySeverity {
		if c.Count != want[c.Severity] {
			t.Errorf("%v count = %d, want %d", c.Severity, c.Count, want[c.Severity])
		}
	}
	if r.Checks[1].Findings != 1 || r.Checks[1].Errors != 1 {
		t.Errorf("nat-idle check info = %+v", r.Checks[1])
	}
}

func TestBuildMinSeverity(t *testing.T) {
	res, metas := sampleResult()
	r := Build(res, metas, Options{MinSeverity: checks.SeverityHigh})
	if r.Summary.Total != 3 || r.Summary.Hidden != 3 {
		t.Fatalf("total = %d hidden = %d, want 3/3", r.Summary.Total, r.Summary.Hidden)
	}
	if math.Abs(r.Summary.EstMonthlyWasteUSD-1234.5) > 1e-9 {
		t.Errorf("waste should only count shown findings, got %v", r.Summary.EstMonthlyWasteUSD)
	}
	empty := Build(scan.Result{}, nil, Options{})
	if empty.MaxSeverity() != 0 || empty.Cost == nil || empty.Errors == nil {
		t.Errorf("empty report = %+v", empty)
	}
}

func TestUSD(t *testing.T) {
	for in, want := range map[float64]string{0: "$0.00", 3.65: "$3.65", 1234.5: "$1,234.50", 1234567.891: "$1,234,567.89", -12: "-$12.00"} {
		if got := usd(in); got != want {
			t.Errorf("usd(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestParseFormat(t *testing.T) {
	for in, want := range map[string]Format{"md": FormatMarkdown, "markdown": FormatMarkdown, "HTML": FormatHTML, "json": FormatJSON} {
		if got, err := ParseFormat(in); err != nil || got != want {
			t.Errorf("ParseFormat(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseFormat("pdf"); err == nil {
		t.Error("expected error for pdf")
	}
}

func render(t *testing.T, format Format, r Report) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, format, r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestHTMLIsSelfContainedAndEscaped(t *testing.T) {
	res, metas := sampleResult()
	out := render(t, FormatHTML, Build(res, metas, Options{Version: "v1.2.3", Demo: true}))

	for _, banned := range []string{"<script", "<link", "src=\"http", "@import", "url("} {
		if strings.Contains(out, banned) {
			t.Errorf("HTML must be self-contained; found %q", banned)
		}
	}
	if strings.Contains(out, "<b>mfa</b>") || !strings.Contains(out, "&lt;b&gt;mfa&lt;/b&gt;") {
		t.Error("finding titles must be HTML-escaped")
	}
	for _, want := range []string{"$1,284.56", "Demo report", "Incomplete scan", "AccessDenied: cloudwatch:GetMetricStatistics", `id="c1"`, `id="s1"`, "@media print", "delete-nat-gateway", "estimate"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
}

func TestMarkdown(t *testing.T) {
	res, metas := sampleResult()
	out := render(t, FormatMarkdown, Build(res, metas, Options{Version: "v1.2.3"}))
	for _, want := range []string{
		"**Estimated monthly waste: $1,284.56**",
		"| C1 | HIGH | $1,234.50 | ap-southeast-1 |",
		`root <b>mfa</b> \| pipe`,
		"```sh\naws ec2 delete-nat-gateway --nat-gateway-id nat-1\n```",
		"| ap-southeast-1 | `nat-idle` | AccessDenied: cloudwatch:GetMetricStatistics |",
		"cloudaudit v1.2.3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	if strings.Contains(out, "Demo report") {
		t.Error("non-demo report must not carry the demo banner")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	res, metas := sampleResult()
	out := render(t, FormatJSON, Build(res, metas, Options{Version: "v1.2.3"}))
	var decoded Report
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Cost) != 3 || decoded.Security[0].Severity != checks.SeverityCritical || decoded.Version != "v1.2.3" {
		t.Errorf("decoded = %+v", decoded)
	}
	if !strings.Contains(out, `"severity": "CRITICAL"`) || !strings.Contains(out, `"est_monthly_waste_usd": 1284.56`) {
		t.Errorf("unexpected JSON shape:\n%s", out[:min(len(out), 600)])
	}
}
