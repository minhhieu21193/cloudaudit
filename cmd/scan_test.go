package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
	"github.com/minhhieu21193/cloudaudit/internal/fakeaws"
)

// stubBackend serves one region with a single HIGH-severity security group
// finding and one LOW cost finding, through the real rules.
type stubBackend struct {
	failRegion string
	gotOpts    *scanOptions
}

func (stubBackend) AccountID(context.Context) (string, error) { return "123456789012", nil }
func (stubBackend) DefaultRegion() string                     { return "ap-northeast-1" }
func (stubBackend) EnabledRegions(context.Context) ([]string, error) {
	return []string{"ap-northeast-1", "ap-southeast-1"}, nil
}

func (s stubBackend) Clients(_ context.Context, region string) (awsapi.Clients, error) {
	if region == s.failRegion {
		return awsapi.Clients{}, errors.New("region disabled")
	}
	return awsapi.Clients{
		EC2: &fakeaws.EC2{
			EBSEncryptionByDefault: true,
			Volumes:                []ec2types.Volume{{VolumeId: aws.String("vol-1"), Size: aws.Int32(10), VolumeType: ec2types.VolumeTypeGp3, State: ec2types.VolumeStateAvailable}},
			SecurityGroups: []ec2types.SecurityGroup{{GroupId: aws.String("sg-1"), IpPermissions: []ec2types.IpPermission{{
				IpProtocol: aws.String("tcp"), FromPort: aws.Int32(22), ToPort: aws.Int32(22), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
			}}}},
		},
	}, nil
}

func runWith(t *testing.T, b stubBackend, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	factory := func(_ context.Context, o *scanOptions) (backend, error) {
		if b.gotOpts != nil {
			*b.gotOpts = *o
		}
		return b, nil
	}
	code = run(context.Background(), args, &out, &errOut, factory)
	return code, out.String(), errOut.String()
}

var ec2Checks = "--checks=ebs-unattached,sg-open-admin-ports,ebs-encryption-default"

func TestScanWritesMarkdownToStdout(t *testing.T) {
	code, out, errOut := runWith(t, stubBackend{}, "scan", ec2Checks)
	if code != ExitOK {
		t.Fatalf("exit %d, stderr %s", code, errOut)
	}
	if !strings.Contains(out, "# AWS Cost & Security Audit") || !strings.Contains(out, "sg-1") || !strings.Contains(out, "vol-1") {
		t.Errorf("stdout:\n%s", out)
	}
	if !strings.Contains(errOut, "Scanning account 123456789012: 3 check(s) in ap-northeast-1") || !strings.Contains(errOut, "2 finding(s)") {
		t.Errorf("stderr = %q", errOut)
	}
}

func TestScanFailOnExitCodes(t *testing.T) {
	tests := []struct {
		failOn string
		want   int
	}{
		{"none", ExitOK},
		{"LOW", ExitFindings},
		{"high", ExitFindings},
		{"CRITICAL", ExitOK},
	}
	for _, tt := range tests {
		code, _, errOut := runWith(t, stubBackend{}, "scan", ec2Checks, "--fail-on", tt.failOn)
		if code != tt.want {
			t.Errorf("--fail-on %s: exit %d, want %d (stderr %s)", tt.failOn, code, tt.want, errOut)
		}
	}
}

func TestScanFailOnIgnoresMinSeverity(t *testing.T) {
	// The LOW cost finding is hidden from the report but still trips --fail-on LOW.
	code, out, _ := runWith(t, stubBackend{}, "scan", "--checks=ebs-unattached", "--min-severity", "HIGH", "--fail-on", "LOW")
	if code != ExitFindings || strings.Contains(out, "vol-1") {
		t.Fatalf("exit %d, report contains hidden finding: %v", code, strings.Contains(out, "vol-1"))
	}
}

func TestScanRegionErrorExitsOneButWritesReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "r.json")
	code, _, errOut := runWith(t, stubBackend{failRegion: "ap-southeast-1"}, "scan", ec2Checks, "--all-regions", "--format", "json", "--out", path)
	if code != ExitError || !strings.Contains(errOut, "Scan incomplete") {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Regions []string `json:"regions"`
		Errors  []struct {
			Region string `json:"region"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Regions) != 2 || len(rep.Errors) != 1 || rep.Errors[0].Region != "ap-southeast-1" {
		t.Errorf("report = %+v", rep)
	}
	if !strings.Contains(errOut, "Report written to "+path) {
		t.Errorf("stderr = %q", errOut)
	}
}

func TestScanFlagValidation(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "--format", "pdf"},
		{"scan", "--min-severity", "urgent"},
		{"scan", "--fail-on", "sometimes"},
		{"scan", "--checks", "no-such-check"},
		{"scan", "--concurrency", "0"},
		{"scan", "--regions", "us-east-1", "--all-regions"},
		{"scan", "unexpected-arg"},
	} {
		if code, _, errOut := runWith(t, stubBackend{}, args...); code != ExitError || errOut == "" {
			t.Errorf("%v: exit %d, stderr %q; want exit 1 with a message", args, code, errOut)
		}
	}
}

func TestScanRegionsFlagDedupes(t *testing.T) {
	var got scanOptions
	code, _, errOut := runWith(t, stubBackend{gotOpts: &got}, "scan", ec2Checks, "--regions", "ap-northeast-1, ap-northeast-1,ap-southeast-1")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.Contains(errOut, "in ap-northeast-1, ap-southeast-1...") {
		t.Errorf("stderr = %q", errOut)
	}
}

func TestChecksCommandListsAll(t *testing.T) {
	code, out, _ := runWith(t, stubBackend{}, "checks")
	if code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	for _, id := range []string{"ebs-unattached", "nat-idle", "sg-open-admin-ports", "root-account", "cloudtrail-multi-region"} {
		if !strings.Contains(out, id) {
			t.Errorf("checks output missing %s", id)
		}
	}
}
