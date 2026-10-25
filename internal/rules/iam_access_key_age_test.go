package rules

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
	"github.com/minhhieu21193/cloudaudit/internal/fakeaws"
)

func accessKey(id string, ageDays int, status iamtypes.StatusType) iamtypes.AccessKeyMetadata {
	return iamtypes.AccessKeyMetadata{AccessKeyId: aws.String(id), CreateDate: aws.Time(daysAgo(ageDays)), Status: status}
}

func TestIAMAccessKeyAge(t *testing.T) {
	fake := &fakeaws.IAM{
		Users: []iamtypes.User{iamUser("svc"), iamUser("dev")},
		AccessKeys: map[string][]iamtypes.AccessKeyMetadata{
			"svc": {
				accessKey("AKIAOLDINUSE0EXAMPLE", 400, iamtypes.StatusTypeActive),
				accessKey("AKIAFRESH000EXAMPLE1", 10, iamtypes.StatusTypeActive),
				accessKey("AKIAINACTIVE0EXAMPLE", 900, iamtypes.StatusTypeInactive),
			},
			"dev": {
				accessKey("AKIAOLDNEVERUSEDEXMP", 200, iamtypes.StatusTypeActive),
				accessKey("AKIASTALEUSE0EXAMPLE", 95, iamtypes.StatusTypeActive),
			},
		},
		KeyLastUsed: map[string]time.Time{
			"AKIAOLDINUSE0EXAMPLE": daysAgo(1),
			"AKIAFRESH000EXAMPLE1": daysAgo(1),
			"AKIASTALEUSE0EXAMPLE": daysAgo(93),
		},
	}
	got, err := IAMAccessKeyAge{}.scan(context.Background(), fake, testEnv(checks.GlobalRegion))
	if err != nil {
		t.Fatal(err)
	}
	m := byResource(t, got)
	if len(m) != 3 {
		t.Fatalf("got %v, want 3 findings", m)
	}
	rotate := m["AKIAOLDINUSE0EXAMPLE"]
	if !strings.Contains(rotate.Title, "400 days old") || !strings.Contains(rotate.FixCommand, "create-access-key --user-name svc") {
		t.Errorf("in-use old key = %+v", rotate)
	}
	for _, id := range []string{"AKIAOLDNEVERUSEDEXMP", "AKIASTALEUSE0EXAMPLE"} {
		f := m[id]
		if !strings.Contains(f.Title, "has not been used") || !strings.Contains(f.FixCommand, "--status Inactive") || strings.Contains(f.FixCommand, "create-access-key") {
			t.Errorf("%s = %+v", id, f)
		}
	}
	if !strings.Contains(m["AKIAOLDNEVERUSEDEXMP"].Evidence, "never used") {
		t.Errorf("evidence = %q", m["AKIAOLDNEVERUSEDEXMP"].Evidence)
	}
}
