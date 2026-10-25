// Package awsclient builds real AWS SDK clients for a scan. It hands them to
// the rules only as awsapi interfaces, which expose read-only operations.
package awsclient

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
)

// fallbackRegion is used for account-level calls (STS, DescribeRegions) when
// the profile has no region configured.
const fallbackRegion = "us-east-1"

type Options struct {
	Profile string
	// RoleARN, if set, is assumed before scanning. This is how an auditor
	// uses the cross-account role from deploy/cloudformation.
	RoleARN    string
	ExternalID string
}

type Session struct {
	cfg aws.Config
}

// Load resolves credentials from the standard AWS chain (env, profile, SSO,
// instance role) and optionally assumes RoleARN.
func Load(ctx context.Context, opts Options) (*Session, error) {
	var loadOpts []func(*config.LoadOptions) error
	if opts.Profile != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(opts.Profile))
	}
	loadOpts = append(loadOpts, config.WithRetryMaxAttempts(5))
	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	if cfg.Region == "" {
		cfg.Region = fallbackRegion
	}
	if opts.RoleARN != "" {
		provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), opts.RoleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = "cloudaudit"
			if opts.ExternalID != "" {
				o.ExternalID = aws.String(opts.ExternalID)
			}
		})
		cfg.Credentials = aws.NewCredentialsCache(provider)
	} else if opts.ExternalID != "" {
		return nil, errors.New("--external-id requires --role-arn")
	}
	return &Session{cfg: cfg}, nil
}

// DefaultRegion is the profile's configured region (or us-east-1).
func (s *Session) DefaultRegion() string { return s.cfg.Region }

func (s *Session) AccountID(ctx context.Context) (string, error) {
	return accountID(ctx, sts.NewFromConfig(s.cfg))
}

func accountID(ctx context.Context, api awsapi.GetCallerIdentityAPI) (string, error) {
	out, err := api.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("get caller identity (are the credentials valid?): %w", err)
	}
	return aws.ToString(out.Account), nil
}

// EnabledRegions lists the regions enabled for the account.
func (s *Session) EnabledRegions(ctx context.Context) ([]string, error) {
	return enabledRegions(ctx, ec2.NewFromConfig(s.cfg))
}

func enabledRegions(ctx context.Context, api awsapi.DescribeRegionsAPI) ([]string, error) {
	// AllRegions=false (the default) returns only regions the account can use.
	out, err := api.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, fmt.Errorf("describe regions: %w", err)
	}
	regions := make([]string, 0, len(out.Regions))
	for _, r := range out.Regions {
		regions = append(regions, aws.ToString(r.RegionName))
	}
	sort.Strings(regions)
	return regions, nil
}

// Clients returns the service clients for one region.
func (s *Session) Clients(_ context.Context, region string) (awsapi.Clients, error) {
	cfg := s.cfg.Copy()
	cfg.Region = region
	return awsapi.Clients{
		EC2:        ec2.NewFromConfig(cfg),
		CloudWatch: cloudwatch.NewFromConfig(cfg),
		ELBv2:      elbv2.NewFromConfig(cfg),
		S3:         s3.NewFromConfig(cfg),
		S3Control:  s3control.NewFromConfig(cfg),
		IAM:        iam.NewFromConfig(cfg),
		RDS:        rds.NewFromConfig(cfg),
		CloudTrail: cloudtrail.NewFromConfig(cfg),
	}, nil
}
