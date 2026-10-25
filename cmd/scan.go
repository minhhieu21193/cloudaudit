package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/minhhieu21193/cloudaudit/internal/checks"
	"github.com/minhhieu21193/cloudaudit/internal/demo"
	"github.com/minhhieu21193/cloudaudit/internal/rules"
	"github.com/minhhieu21193/cloudaudit/internal/scan"
	"github.com/minhhieu21193/cloudaudit/pkg/report"
	"github.com/spf13/cobra"
)

type scanOptions struct {
	profile         string
	roleARN         string
	externalID      string
	regions         []string
	allRegions      bool
	checkIDs        []string
	format          string
	out             string
	minSeverity     string
	failOn          string
	concurrency     int
	snapshotAgeDays int
	stoppedDays     int
	demo            bool
}

func newScanCmd(newBackend backendFactory) *cobra.Command {
	o := &scanOptions{}
	c := &cobra.Command{
		Use:   "scan",
		Short: "Scan an AWS account and write a report",
		Long: `Scan runs every check (or those given with --checks) in the selected regions
and writes a report. Only read-only Describe/Get/List API calls are made.

Exit codes: 0 no findings at or above --fail-on, 2 findings at or above
--fail-on, 1 error (including a partial scan; the report is still written).`,
		Example: `  cloudaudit scan --demo --format html --out report.html
  cloudaudit scan --profile client-audit --regions ap-northeast-1,ap-southeast-1 --format html --out report.html
  cloudaudit scan --role-arn arn:aws:iam::111122223333:role/CloudAuditReadOnly --external-id <id> --all-regions
  cloudaudit scan --checks sg-open-admin-ports,root-account --fail-on HIGH --format json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScan(cmd.Context(), o, newBackend, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	f := c.Flags()
	f.StringVar(&o.profile, "profile", "", "AWS shared config profile (default: the standard credential chain)")
	f.StringVar(&o.roleARN, "role-arn", "", "IAM role to assume before scanning, e.g. the cross-account audit role")
	f.StringVar(&o.externalID, "external-id", "", "external ID required by the role trust policy")
	f.StringSliceVar(&o.regions, "regions", nil, "comma-separated regions to scan (default: the profile's region)")
	f.BoolVar(&o.allRegions, "all-regions", false, "scan every region enabled for the account")
	f.StringSliceVar(&o.checkIDs, "checks", nil, "only run these check IDs (see 'cloudaudit checks')")
	f.StringVar(&o.format, "format", "md", "report format: md, html or json")
	f.StringVar(&o.out, "out", "", "write the report to this file instead of stdout")
	f.StringVar(&o.minSeverity, "min-severity", "LOW", "hide findings below this severity: LOW, MEDIUM, HIGH, CRITICAL")
	f.StringVar(&o.failOn, "fail-on", "none", "exit 2 if any finding is at or above this severity (none disables)")
	f.IntVar(&o.concurrency, "concurrency", 4, "regions scanned in parallel")
	f.IntVar(&o.snapshotAgeDays, "snapshot-age-days", checks.DefaultConfig().SnapshotMinAgeDays, "minimum age for ebs-snapshot-orphaned")
	f.IntVar(&o.stoppedDays, "stopped-days", checks.DefaultConfig().StoppedMinDays, "minimum days stopped for ec2-stopped")
	f.BoolVar(&o.demo, "demo", false, "scan a built-in fictional account instead of AWS (no credentials needed)")
	c.MarkFlagsMutuallyExclusive("regions", "all-regions")
	for _, awsFlag := range []string{"profile", "role-arn", "external-id"} {
		c.MarkFlagsMutuallyExclusive("demo", awsFlag)
	}
	return c
}

func runScan(ctx context.Context, o *scanOptions, newBackend backendFactory, stdout, stderr io.Writer) error {
	format, err := report.ParseFormat(o.format)
	if err != nil {
		return err
	}
	minSev, err := checks.ParseSeverity(o.minSeverity)
	if err != nil {
		return fmt.Errorf("--min-severity: %w", err)
	}
	var failOn checks.Severity
	if !strings.EqualFold(o.failOn, "none") {
		if failOn, err = checks.ParseSeverity(o.failOn); err != nil {
			return fmt.Errorf("--fail-on: %w", err)
		}
	}
	if o.concurrency < 1 || o.snapshotAgeDays < 1 || o.stoppedDays < 1 {
		return errors.New("--concurrency, --snapshot-age-days and --stopped-days must be at least 1")
	}
	selected, err := scan.Filter(rules.All(), o.checkIDs)
	if err != nil {
		return err
	}
	cfg := checks.DefaultConfig()
	cfg.SnapshotMinAgeDays = o.snapshotAgeDays
	cfg.StoppedMinDays = o.stoppedDays

	var b backend
	if o.demo {
		// Never touches AWS: no config is loaded and no client is created.
		b = demo.New(time.Now())
	} else if b, err = newBackend(ctx, o); err != nil {
		return err
	}
	accountID, err := b.AccountID(ctx)
	if err != nil {
		return err
	}
	regions, err := resolveRegions(ctx, o, b)
	if err != nil {
		return err
	}

	fmt.Fprintf(stderr, "Scanning account %s: %d check(s) in %s...\n", accountID, len(selected), strings.Join(regions, ", "))
	res := scan.Run(ctx, scan.Options{
		Regions:     regions,
		Checks:      selected,
		Concurrency: o.concurrency,
		Config:      cfg,
		AccountID:   accountID,
	}, b.Clients)

	metas := make([]checks.Meta, 0, len(selected))
	for _, c := range selected {
		metas = append(metas, c.Meta())
	}
	rep := report.Build(res, metas, report.Options{Version: toolVersion(), Demo: isDemo(b), MinSeverity: minSev})

	var buf bytes.Buffer
	if err := report.Write(&buf, format, rep); err != nil {
		return fmt.Errorf("render report: %w", err)
	}
	if o.out == "" {
		if _, err := stdout.Write(buf.Bytes()); err != nil {
			return err
		}
	} else {
		if err := writeFile(o.out, buf.Bytes()); err != nil {
			return err
		}
	}

	fmt.Fprintf(stderr, "%d finding(s) (%s); estimated monthly waste %s (estimate).%s\n",
		rep.Summary.Total, severityLine(rep), usdShort(rep.Summary.EstMonthlyWasteUSD), outNote(o.out))

	if len(res.Errors) > 0 {
		return &exitError{code: ExitError, msg: fmt.Sprintf("Scan incomplete: %d region/check error(s); see the report's coverage section.", len(res.Errors))}
	}
	if failOn > 0 {
		for _, f := range res.Findings {
			if f.Severity >= failOn {
				return &exitError{code: ExitFindings, msg: fmt.Sprintf("Findings at or above %s (--fail-on).", failOn)}
			}
		}
	}
	return nil
}

func resolveRegions(ctx context.Context, o *scanOptions, b backend) ([]string, error) {
	if o.allRegions || (isDemo(b) && len(o.regions) == 0) {
		return b.EnabledRegions(ctx)
	}
	var regions []string
	seen := map[string]bool{}
	for _, r := range o.regions {
		r = strings.TrimSpace(r)
		if r != "" && !seen[r] {
			seen[r] = true
			regions = append(regions, r)
		}
	}
	if len(regions) == 0 {
		regions = []string{b.DefaultRegion()}
	}
	return regions, nil
}

func writeFile(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("create output directory: %w", err)
		}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

func severityLine(r report.Report) string {
	parts := make([]string, 0, len(r.Summary.BySeverity))
	for _, c := range r.Summary.BySeverity {
		parts = append(parts, fmt.Sprintf("%d %s", c.Count, strings.ToLower(c.Severity.String())))
	}
	return strings.Join(parts, ", ")
}

func usdShort(v float64) string { return fmt.Sprintf("$%.2f/month", v) }

func outNote(path string) string {
	if path == "" {
		return ""
	}
	return " Report written to " + path + "."
}
