package rules

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
)

const noPABCode = "NoSuchPublicAccessBlockConfiguration"

const pabAllOn = "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

// pab is a Block Public Access configuration; a missing configuration is all
// false.
type pab struct{ blockACLs, ignoreACLs, blockPolicy, restrictBuckets bool }

func (p pab) or(o pab) pab {
	return pab{p.blockACLs || o.blockACLs, p.ignoreACLs || o.ignoreACLs, p.blockPolicy || o.blockPolicy, p.restrictBuckets || o.restrictBuckets}
}

func (p pab) allOn() bool { return p.blockACLs && p.ignoreACLs && p.blockPolicy && p.restrictBuckets }

func (p pab) off() string {
	settings := []struct {
		name string
		on   bool
	}{
		{"BlockPublicAcls", p.blockACLs},
		{"IgnorePublicAcls", p.ignoreACLs},
		{"BlockPublicPolicy", p.blockPolicy},
		{"RestrictPublicBuckets", p.restrictBuckets},
	}
	var off []string
	for _, s := range settings {
		if !s.on {
			off = append(off, s.name)
		}
	}
	return strings.Join(off, ", ")
}

// S3PublicAccessBlock flags an account without full Block Public Access and,
// when the account setting does not already cover them, buckets without it.
type S3PublicAccessBlock struct{}

func (S3PublicAccessBlock) Meta() checks.Meta {
	return checks.Meta{
		ID:       "s3-public-access-block",
		Name:     "S3 Block Public Access not fully enabled",
		Category: checks.CategorySecurity,
		Global:   true,
		DocsURL:  "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
	}
}

func (c S3PublicAccessBlock) Run(ctx context.Context, env *checks.Env) ([]checks.Finding, error) {
	return c.scan(ctx, env.Clients.S3, env.Clients.S3Control, env)
}

func (c S3PublicAccessBlock) scan(ctx context.Context, api awsapi.S3, ctl awsapi.GetAccountPublicAccessBlockAPI, env *checks.Env) ([]checks.Finding, error) {
	if env.AccountID == "" {
		return nil, errors.New("account ID unknown; cannot read account-level Block Public Access")
	}
	meta := c.Meta()
	var findings []checks.Finding

	var account pab
	out, err := ctl.GetPublicAccessBlock(ctx, &s3control.GetPublicAccessBlockInput{AccountId: aws.String(env.AccountID)})
	switch {
	case isAPIError(err, noPABCode):
	case err != nil:
		return nil, fmt.Errorf("get account public access block: %w", err)
	default:
		cfg := out.PublicAccessBlockConfiguration
		account = pab{aws.ToBool(cfg.BlockPublicAcls), aws.ToBool(cfg.IgnorePublicAcls), aws.ToBool(cfg.BlockPublicPolicy), aws.ToBool(cfg.RestrictPublicBuckets)}
	}
	if account.allOn() {
		return nil, nil // covers every bucket, current and future
	}

	f := meta.NewFinding(env, "account/"+env.AccountID)
	f.Title = "Account-level S3 Block Public Access is not fully enabled"
	f.Severity = checks.SeverityHigh
	f.Evidence = "Settings off at account level: " + account.off() + ". Any bucket can be made public by a policy or ACL change."
	f.Recommendation = "Turn on all four settings at account level unless a bucket must serve public content directly; serve such content through CloudFront with Origin Access Control instead."
	f.FixCommand = fmt.Sprintf("aws s3control put-public-access-block --account-id %s --public-access-block-configuration %s", env.AccountID, pabAllOn)
	findings = append(findings, f)

	pages := s3.NewListBucketsPaginator(api, &s3.ListBucketsInput{})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list buckets: %w", err)
		}
		for _, b := range page.Buckets {
			name := aws.ToString(b.Name)
			region := aws.ToString(b.BucketRegion)
			var bucket pab
			out, err := api.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: b.Name}, inRegion(region))
			switch {
			case isAPIError(err, noPABCode):
			case err != nil:
				return nil, fmt.Errorf("get public access block for bucket %s: %w", name, err)
			default:
				cfg := out.PublicAccessBlockConfiguration
				bucket = pab{aws.ToBool(cfg.BlockPublicAcls), aws.ToBool(cfg.IgnorePublicAcls), aws.ToBool(cfg.BlockPublicPolicy), aws.ToBool(cfg.RestrictPublicBuckets)}
			}
			effective := bucket.or(account)
			if effective.allOn() {
				continue
			}
			bf := meta.NewFinding(env, name)
			bf.Title = fmt.Sprintf("S3 bucket %s is not protected by Block Public Access", name)
			bf.Severity = checks.SeverityMedium
			bf.Evidence = fmt.Sprintf("Bucket in %s. Effective settings off (bucket and account combined): %s.", region, effective.off())
			bf.Recommendation = "Enable all four settings on the bucket unless it intentionally serves public objects. Review its bucket policy and ACLs for public grants first."
			bf.FixCommand = fmt.Sprintf("aws s3api put-public-access-block --bucket %s --public-access-block-configuration %s", name, pabAllOn)
			findings = append(findings, bf)
		}
	}
	return findings, nil
}

// inRegion sends a bucket-level request to the bucket's own region, which
// S3 requires.
func inRegion(region string) func(*s3.Options) {
	return func(o *s3.Options) {
		if region != "" {
			o.Region = region
		}
	}
}
