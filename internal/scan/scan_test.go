package scan

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
)

type stubCheck struct {
	id     string
	global bool
	run    func(env *checks.Env) ([]checks.Finding, error)
}

func (s stubCheck) Meta() checks.Meta {
	return checks.Meta{ID: s.id, Name: s.id, Category: checks.CategoryCost, Global: s.global}
}

func (s stubCheck) Run(_ context.Context, env *checks.Env) ([]checks.Finding, error) {
	return s.run(env)
}

func emit(id string) func(env *checks.Env) ([]checks.Finding, error) {
	return func(env *checks.Env) ([]checks.Finding, error) {
		return []checks.Finding{{CheckID: id, Region: env.Region, ResourceID: "r-" + env.Region}}, nil
	}
}

func okFactory(context.Context, string) (awsapi.Clients, error) { return awsapi.Clients{}, nil }

func TestRunRegionalAndGlobal(t *testing.T) {
	var globalEnvRegion string
	global := stubCheck{id: "g", global: true, run: func(env *checks.Env) ([]checks.Finding, error) {
		globalEnvRegion = env.Region
		return []checks.Finding{{CheckID: "g", Region: env.Region, ResourceID: "acct"}}, nil
	}}
	res := Run(context.Background(), Options{
		Regions:     []string{"ap-southeast-1", "ap-northeast-1"},
		Checks:      []checks.Check{stubCheck{id: "r", run: emit("r")}, global},
		Concurrency: 2,
	}, okFactory)

	if len(res.Errors) != 0 {
		t.Fatalf("unexpected errors %+v", res.Errors)
	}
	if len(res.Findings) != 3 {
		t.Fatalf("got %d findings, want 3 (2 regional + 1 global): %+v", len(res.Findings), res.Findings)
	}
	if globalEnvRegion != checks.GlobalRegion {
		t.Errorf("global check env.Region = %q, want %q", globalEnvRegion, checks.GlobalRegion)
	}
	// Sorted by region: ap-northeast-1, ap-southeast-1, global.
	if res.Findings[0].Region != "ap-northeast-1" || res.Findings[2].Region != checks.GlobalRegion {
		t.Errorf("findings not sorted: %+v", res.Findings)
	}
	if strings.Join(res.CheckIDs, ",") != "r,g" {
		t.Errorf("CheckIDs = %v", res.CheckIDs)
	}
}

func TestGlobalChecksUseFirstRegionClients(t *testing.T) {
	var used []string
	factory := func(_ context.Context, region string) (awsapi.Clients, error) {
		used = append(used, region)
		return awsapi.Clients{}, nil
	}
	Run(context.Background(), Options{
		Regions: []string{"eu-west-1", "us-west-2"},
		Checks:  []checks.Check{stubCheck{id: "g", global: true, run: emit("g")}},
	}, factory)
	if len(used) != 1 || used[0] != "eu-west-1" {
		t.Fatalf("global-only scan built clients for %v, want [eu-west-1]", used)
	}
}

func TestFailingRegionDoesNotStopScan(t *testing.T) {
	factory := func(_ context.Context, region string) (awsapi.Clients, error) {
		if region == "bad-1" {
			return awsapi.Clients{}, errors.New("region not enabled")
		}
		return awsapi.Clients{}, nil
	}
	failing := stubCheck{id: "flaky", run: func(env *checks.Env) ([]checks.Finding, error) {
		if env.Region == "us-west-2" {
			return nil, errors.New("AccessDenied")
		}
		return emit("flaky")(env)
	}}
	panicky := stubCheck{id: "panicky", run: func(*checks.Env) ([]checks.Finding, error) { panic("boom") }}

	res := Run(context.Background(), Options{
		Regions:     []string{"us-east-1", "bad-1", "us-west-2"},
		Checks:      []checks.Check{failing, panicky},
		Concurrency: 3,
	}, factory)

	if len(res.Findings) != 1 || res.Findings[0].Region != "us-east-1" {
		t.Fatalf("findings = %+v, want one from us-east-1", res.Findings)
	}
	var regionErr, checkErr, panicErrs int
	for _, e := range res.Errors {
		switch {
		case e.Region == "bad-1" && e.CheckID == "":
			regionErr++
		case e.Region == "us-west-2" && e.CheckID == "flaky":
			checkErr++
		case e.CheckID == "panicky" && strings.Contains(e.Message, "panicked"):
			panicErrs++
		}
	}
	if regionErr != 1 || checkErr != 1 || panicErrs != 2 {
		t.Fatalf("errors = %+v", res.Errors)
	}
}

func TestConcurrencyIsBounded(t *testing.T) {
	var inFlight, peak atomic.Int32
	slow := stubCheck{id: "slow", run: func(env *checks.Env) ([]checks.Finding, error) {
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		inFlight.Add(-1)
		return nil, nil
	}}
	regions := []string{"r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8"}
	Run(context.Background(), Options{Regions: regions, Checks: []checks.Check{slow}, Concurrency: 3}, okFactory)
	if p := peak.Load(); p > 3 || p < 2 {
		t.Fatalf("peak concurrency = %d, want 2..3", p)
	}
}

func TestCancelledContextRecordsErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := Run(ctx, Options{Regions: []string{"r1"}, Checks: []checks.Check{stubCheck{id: "c", run: emit("c")}}}, okFactory)
	if len(res.Errors) != 1 || len(res.Findings) != 0 {
		t.Fatalf("res = %+v", res)
	}
}

func TestFilter(t *testing.T) {
	all := []checks.Check{stubCheck{id: "a"}, stubCheck{id: "b"}, stubCheck{id: "c"}}
	got, err := Filter(all, []string{"c", " a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Meta().ID != "a" || got[1].Meta().ID != "c" {
		t.Fatalf("Filter = %v", got)
	}
	if got, _ := Filter(all, nil); len(got) != 3 {
		t.Fatal("empty filter should select all")
	}
	if _, err := Filter(all, []string{"a", "nope"}); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("err = %v", err)
	}
}
