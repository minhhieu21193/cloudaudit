package rules

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
)

// EBSEncryptionDefault flags regions where new EBS volumes are not encrypted
// by default.
type EBSEncryptionDefault struct{}

func (EBSEncryptionDefault) Meta() checks.Meta {
	return checks.Meta{
		ID:       "ebs-encryption-default",
		Name:     "EBS encryption by default disabled",
		Category: checks.CategorySecurity,
		DocsURL:  "https://docs.aws.amazon.com/ebs/latest/userguide/encryption-by-default.html",
	}
}

func (c EBSEncryptionDefault) Run(ctx context.Context, env *checks.Env) ([]checks.Finding, error) {
	return c.scan(ctx, env.Clients.EC2, env)
}

func (c EBSEncryptionDefault) scan(ctx context.Context, api awsapi.GetEbsEncryptionByDefaultAPI, env *checks.Env) ([]checks.Finding, error) {
	out, err := api.GetEbsEncryptionByDefault(ctx, &ec2.GetEbsEncryptionByDefaultInput{})
	if err != nil {
		return nil, fmt.Errorf("get EBS encryption by default: %w", err)
	}
	if aws.ToBool(out.EbsEncryptionByDefault) {
		return nil, nil
	}
	f := c.Meta().NewFinding(env, "ebs-encryption-by-default")
	f.Title = fmt.Sprintf("EBS encryption by default is off in %s", env.Region)
	f.Severity = checks.SeverityMedium
	f.Evidence = "GetEbsEncryptionByDefault returned false: new volumes and snapshot copies in this region are created unencrypted unless each request asks for encryption."
	f.Recommendation = "Turn on encryption by default. It applies to new volumes only; existing unencrypted volumes need a snapshot, an encrypted copy and a restore."
	f.FixCommand = fmt.Sprintf("aws ec2 enable-ebs-encryption-by-default --region %s", env.Region)
	return []checks.Finding{f}, nil
}
