// Package scan runs checks across regions with a bounded worker pool. A
// failing region or check is recorded in the result and never aborts the
// rest of the scan.
package scan

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
)

// ClientFactory builds the service clients for one region.
type ClientFactory func(ctx context.Context, region string) (awsapi.Clients, error)

type Options struct {
	Regions     []string
	Checks      []checks.Check
	Concurrency int
	Config      checks.Config
	AccountID   string
	// GlobalRegion is where account-wide APIs are called. Defaults to the
	// first entry of Regions.
	GlobalRegion string
	Now          func() time.Time
}

// Error records a region or check that could not be scanned. CheckID is
// empty when the whole region failed (for example, its clients could not be
// built).
type Error struct {
	Region  string `json:"region"`
	CheckID string `json:"check_id,omitempty"`
	Message string `json:"message"`
}

type Result struct {
	AccountID string           `json:"account_id,omitempty"`
	StartedAt time.Time        `json:"started_at"`
	Duration  time.Duration    `json:"duration_ns"`
	Regions   []string         `json:"regions"`
	CheckIDs  []string         `json:"checks"`
	Findings  []checks.Finding `json:"findings"`
	Errors    []Error          `json:"errors"`
}

type job struct {
	region       string // label used in findings
	clientRegion string // region the clients are built for
	checks       []checks.Check
}

// Run executes opts.Checks in every region and returns once all jobs finish.
func Run(ctx context.Context, opts Options, factory ClientFactory) Result {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	start := now()
	res := Result{
		AccountID: opts.AccountID,
		StartedAt: start,
		Regions:   slices.Clone(opts.Regions),
		Findings:  []checks.Finding{},
		Errors:    []Error{},
	}
	for _, c := range opts.Checks {
		res.CheckIDs = append(res.CheckIDs, c.Meta().ID)
	}

	var regional, global []checks.Check
	for _, c := range opts.Checks {
		if c.Meta().Global {
			global = append(global, c)
		} else {
			regional = append(regional, c)
		}
	}

	var jobs []job
	if len(global) > 0 {
		gr := opts.GlobalRegion
		if gr == "" && len(opts.Regions) > 0 {
			gr = opts.Regions[0]
		}
		jobs = append(jobs, job{region: checks.GlobalRegion, clientRegion: gr, checks: global})
	}
	if len(regional) > 0 {
		for _, r := range opts.Regions {
			jobs = append(jobs, job{region: r, clientRegion: r, checks: regional})
		}
	}

	workers := opts.Concurrency
	if workers < 1 {
		workers = 1
	}
	workers = min(workers, max(len(jobs), 1))

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		pending = make(chan job)
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range pending {
				findings, errs := runJob(ctx, j, opts, start, factory)
				mu.Lock()
				res.Findings = append(res.Findings, findings...)
				res.Errors = append(res.Errors, errs...)
				mu.Unlock()
			}
		}()
	}
	for _, j := range jobs {
		pending <- j
	}
	close(pending)
	wg.Wait()

	sortFindings(res.Findings)
	sort.Slice(res.Errors, func(i, k int) bool {
		a, b := res.Errors[i], res.Errors[k]
		return cmp.Or(cmp.Compare(a.Region, b.Region), cmp.Compare(a.CheckID, b.CheckID)) < 0
	})
	res.Duration = now().Sub(start)
	return res
}

func runJob(ctx context.Context, j job, opts Options, start time.Time, factory ClientFactory) ([]checks.Finding, []Error) {
	clients, err := factory(ctx, j.clientRegion)
	if err != nil {
		return nil, []Error{{Region: j.region, Message: fmt.Sprintf("create clients: %v", err)}}
	}
	env := &checks.Env{
		Region:    j.region,
		AccountID: opts.AccountID,
		Now:       start,
		Config:    opts.Config,
		Clients:   clients,
	}
	var findings []checks.Finding
	var errs []Error
	for _, c := range j.checks {
		if ctx.Err() != nil {
			errs = append(errs, Error{Region: j.region, CheckID: c.Meta().ID, Message: ctx.Err().Error()})
			continue
		}
		fs, err := runCheck(ctx, c, env)
		if err != nil {
			errs = append(errs, Error{Region: j.region, CheckID: c.Meta().ID, Message: err.Error()})
			continue
		}
		findings = append(findings, fs...)
	}
	return findings, errs
}

// runCheck shields the scan from a panicking check.
func runCheck(ctx context.Context, c checks.Check, env *checks.Env) (fs []checks.Finding, err error) {
	defer func() {
		if r := recover(); r != nil {
			fs, err = nil, fmt.Errorf("check panicked: %v", r)
		}
	}()
	return c.Run(ctx, env)
}

func sortFindings(fs []checks.Finding) {
	slices.SortStableFunc(fs, func(a, b checks.Finding) int {
		return cmp.Or(
			cmp.Compare(a.Region, b.Region),
			cmp.Compare(a.CheckID, b.CheckID),
			cmp.Compare(a.ResourceID, b.ResourceID),
		)
	})
}

// Filter returns the checks whose IDs are listed, in the order of all. An
// empty ids list selects every check. Unknown IDs are an error.
func Filter(all []checks.Check, ids []string) ([]checks.Check, error) {
	if len(ids) == 0 {
		return all, nil
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[strings.TrimSpace(id)] = true
	}
	var out []checks.Check
	for _, c := range all {
		if want[c.Meta().ID] {
			out = append(out, c)
			delete(want, c.Meta().ID)
		}
	}
	if len(want) > 0 {
		unknown := make([]string, 0, len(want))
		for id := range want {
			unknown = append(unknown, id)
		}
		sort.Strings(unknown)
		return nil, fmt.Errorf("unknown check ID(s): %s", strings.Join(unknown, ", "))
	}
	return out, nil
}
