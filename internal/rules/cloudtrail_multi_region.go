package rules

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
)

// CloudTrailMultiRegion flags an account with no multi-region trail that is
// currently logging.
type CloudTrailMultiRegion struct{}

func (CloudTrailMultiRegion) Meta() checks.Meta {
	return checks.Meta{
		ID:       "cloudtrail-multi-region",
		Name:     "No logging multi-region CloudTrail trail",
		Category: checks.CategorySecurity,
		Global:   true,
		DocsURL:  "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html",
	}
}

func (c CloudTrailMultiRegion) Run(ctx context.Context, env *checks.Env) ([]checks.Finding, error) {
	return c.scan(ctx, env.Clients.CloudTrail, env)
}

func (c CloudTrailMultiRegion) scan(ctx context.Context, api awsapi.CloudTrail, env *checks.Env) ([]checks.Finding, error) {
	// Shadow trails make multi-region and organization trails homed in
	// another region visible here.
	out, err := api.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{IncludeShadowTrails: aws.Bool(true)})
	if err != nil {
		return nil, fmt.Errorf("describe trails: %w", err)
	}
	var seen []string
	for _, t := range out.TrailList {
		name := aws.ToString(t.Name)
		if !aws.ToBool(t.IsMultiRegionTrail) {
			seen = append(seen, name+" (single-region)")
			continue
		}
		// The ARN works from any region; the bare name only from the home region.
		status, err := api.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: t.TrailARN})
		if err != nil {
			return nil, fmt.Errorf("get trail status for %s: %w", name, err)
		}
		if aws.ToBool(status.IsLogging) {
			return nil, nil
		}
		seen = append(seen, name+" (multi-region, logging stopped)")
	}

	evidence := "DescribeTrails returned no trails."
	if len(seen) > 0 {
		evidence = "Trails found: " + strings.Join(seen, "; ") + ". None is both multi-region and logging."
	}
	f := c.Meta().NewFinding(env, "cloudtrail")
	f.Title = "No multi-region CloudTrail trail is logging"
	f.Severity = checks.SeverityHigh
	f.Evidence = evidence
	f.Recommendation = "Create one multi-region trail (or an organization trail) delivering to a dedicated, access-restricted S3 bucket, with log file validation on. Without it there is no durable record of API activity for incident response."
	f.FixCommand = "aws cloudtrail create-trail --name account-audit --s3-bucket-name <log-bucket> --is-multi-region-trail --enable-log-file-validation\naws cloudtrail start-logging --name account-audit"
	return []checks.Finding{f}, nil
}
