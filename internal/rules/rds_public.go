package rules

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
)

// RDSPublic flags RDS instances with PubliclyAccessible set, which gives them
// a public DNS name and IP address.
type RDSPublic struct{}

func (RDSPublic) Meta() checks.Meta {
	return checks.Meta{
		ID:       "rds-public",
		Name:     "Publicly accessible RDS instances",
		Category: checks.CategorySecurity,
		DocsURL:  "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html#USER_VPC.Hiding",
	}
}

func (c RDSPublic) Run(ctx context.Context, env *checks.Env) ([]checks.Finding, error) {
	return c.scan(ctx, env.Clients.RDS, env)
}

func (c RDSPublic) scan(ctx context.Context, api awsapi.DescribeDBInstancesAPI, env *checks.Env) ([]checks.Finding, error) {
	dbs, err := listDBInstances(ctx, api)
	if err != nil {
		return nil, err
	}
	meta := c.Meta()
	var findings []checks.Finding
	for _, db := range dbs {
		if !aws.ToBool(db.PubliclyAccessible) {
			continue
		}
		id := aws.ToString(db.DBInstanceIdentifier)
		endpoint := ""
		if db.Endpoint != nil {
			endpoint = fmt.Sprintf(" Endpoint %s:%d.", aws.ToString(db.Endpoint.Address), aws.ToInt32(db.Endpoint.Port))
		}
		f := meta.NewFinding(env, id)
		f.Title = fmt.Sprintf("RDS instance %s is publicly accessible", dbLabel(db))
		f.Severity = checks.SeverityHigh
		f.Evidence = "PubliclyAccessible=true: the instance has a public IP, and only its security groups stand between it and the internet." + endpoint
		f.Recommendation = "Turn off public access and connect from inside the VPC (application subnets, a bastion via SSM, or a VPN). Check the instance's security groups for 0.0.0.0/0 rules too."
		f.FixCommand = fmt.Sprintf("aws rds modify-db-instance --region %s --db-instance-identifier %s --no-publicly-accessible --apply-immediately", env.Region, id)
		findings = append(findings, f)
	}
	return findings, nil
}
