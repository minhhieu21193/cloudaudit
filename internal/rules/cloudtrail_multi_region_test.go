package rules

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
	"github.com/minhhieu21193/cloudaudit/internal/fakeaws"
)

func trail(name string, multi bool) cttypes.Trail {
	return cttypes.Trail{Name: aws.String(name), TrailARN: aws.String("arn:aws:cloudtrail:us-east-1:123456789012:trail/" + name), IsMultiRegionTrail: aws.Bool(multi)}
}

func TestCloudTrailMultiRegion(t *testing.T) {
	tests := []struct {
		name         string
		trails       []cttypes.Trail
		logging      map[string]bool
		wantFinding  bool
		wantEvidence string
	}{
		{"none", nil, nil, true, "no trails"},
		{"single region only", []cttypes.Trail{trail("local", false)}, nil, true, "local (single-region)"},
		{"multi region stopped", []cttypes.Trail{trail("org", true)}, map[string]bool{"arn:aws:cloudtrail:us-east-1:123456789012:trail/org": false}, true, "logging stopped"},
		{"multi region logging", []cttypes.Trail{trail("local", false), trail("org", true)}, map[string]bool{"arn:aws:cloudtrail:us-east-1:123456789012:trail/org": true}, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CloudTrailMultiRegion{}.scan(context.Background(), &fakeaws.CloudTrail{Trails: tt.trails, Logging: tt.logging}, testEnv(checks.GlobalRegion))
			if err != nil {
				t.Fatal(err)
			}
			if (len(got) == 1) != tt.wantFinding {
				t.Fatalf("got %+v, wantFinding %v", got, tt.wantFinding)
			}
			if tt.wantFinding && !strings.Contains(got[0].Evidence, tt.wantEvidence) {
				t.Errorf("evidence = %q, want it to contain %q", got[0].Evidence, tt.wantEvidence)
			}
		})
	}
}
