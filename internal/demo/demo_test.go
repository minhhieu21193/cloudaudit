package demo

import (
	"context"
	"testing"
	"time"

	"github.com/minhhieu21193/cloudaudit/internal/checks"
	"github.com/minhhieu21193/cloudaudit/internal/rules"
	"github.com/minhhieu21193/cloudaudit/internal/scan"
)

func runDemo(t *testing.T) scan.Result {
	t.Helper()
	now := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	b := New(now)
	regions, err := b.EnabledRegions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return scan.Run(context.Background(), scan.Options{
		Regions:     regions,
		Checks:      rules.All(),
		Concurrency: 4,
		Config:      checks.DefaultConfig(),
		AccountID:   AccountID,
		Now:         func() time.Time { return now },
	}, b.Clients)
}

// The demo exists to show every check; if a rule changes and stops matching
// its demo data, this test says which one.
func TestDemoExercisesEveryCheckWithoutErrors(t *testing.T) {
	res := runDemo(t)
	if len(res.Errors) != 0 {
		t.Fatalf("demo scan errors: %+v", res.Errors)
	}
	perCheck := map[string]int{}
	for _, f := range res.Findings {
		perCheck[f.CheckID]++
	}
	for _, c := range rules.All() {
		if perCheck[c.Meta().ID] == 0 {
			t.Errorf("check %s produced no findings in demo mode", c.Meta().ID)
		}
	}
}

func TestDemoSkipsHealthyResources(t *testing.T) {
	res := runDemo(t)
	healthy := map[string]bool{
		"vol-0e5f7a9b2c3d68024":                             true, // gp3 root
		"vol-01a2b3c4d5e6f7081":                             true, // gp2 on long-stopped instance: counted by ec2-stopped, not gp2-to-gp3
		"i-0d45e67f89a01b234":                               true, // stopped only 6 days
		"snap-0e5f4a3b2c1d00756":                            true, // backs an AMI
		"snap-0f4a3b2c1d0e90867":                            true, // source volume exists
		"snap-01b2c3d4e5f6a7978":                            true, // too recent
		"nat-0a1b2c3d4e5f60789":                             true, // busy
		"sg-0c3d4e5f6a7b8293a":                              true, // 80/443 only
		"sg-0d4e5f6a7b8c9304b":                              true, // private CIDR
		"prod-orders":                                       true, // encrypted, private
		"examplecorp-prod-assets":                           true,
		"AKIAJEXAMPLETERRAFRM":                              true, // fresh key
		lbARN(tokyo, "app", "prod-web", "5f3a8c1e9b7d2046"): true,
	}
	for _, f := range res.Findings {
		if healthy[f.ResourceID] {
			t.Errorf("healthy resource %s flagged by %s", f.ResourceID, f.CheckID)
		}
	}
}

func TestDemoUnknownRegionIsEmpty(t *testing.T) {
	c, err := New(time.Now()).Clients(context.Background(), "eu-west-1")
	if err != nil || c.EC2 == nil || c.IAM == nil {
		t.Fatalf("clients = %+v, err %v", c, err)
	}
}
