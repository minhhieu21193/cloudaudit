package rules

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
	"github.com/minhhieu21193/cloudaudit/internal/pricing"
)

// EBSUnattached flags EBS volumes in the "available" state: they are billed
// for provisioned storage while attached to nothing.
type EBSUnattached struct{}

func (EBSUnattached) Meta() checks.Meta {
	return checks.Meta{
		ID:       "ebs-unattached",
		Name:     "Unattached EBS volumes",
		Category: checks.CategoryCost,
		DocsURL:  "https://docs.aws.amazon.com/ebs/latest/userguide/ebs-deleting-volume.html",
	}
}

func (c EBSUnattached) Run(ctx context.Context, env *checks.Env) ([]checks.Finding, error) {
	return c.scan(ctx, env.Clients.EC2, env)
}

func (c EBSUnattached) scan(ctx context.Context, api awsapi.DescribeVolumesAPI, env *checks.Env) ([]checks.Finding, error) {
	prices, exact := pricing.For(env.Region)
	meta := c.Meta()
	var findings []checks.Finding

	pages := ec2.NewDescribeVolumesPaginator(api, &ec2.DescribeVolumesInput{
		Filters: []ec2types.Filter{{Name: aws.String("status"), Values: []string{"available"}}},
	})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe volumes: %w", err)
		}
		for _, v := range page.Volumes {
			id := aws.ToString(v.VolumeId)
			size := aws.ToInt32(v.Size)
			volType := string(v.VolumeType)
			cost := prices.EBSMonthly(volType, size)

			f := meta.NewFinding(env, id)
			f.Title = fmt.Sprintf("Unattached %s volume %s (%d GiB)", volType, withName(id, ec2Name(v.Tags)), size)
			f.Severity = costSeverity(cost)
			f.EstMonthlyUSD = cost
			f.Evidence = fmt.Sprintf("State is available (attached to nothing). Created %s, %d days ago. %d GiB %s at $%.3f/GB-month (storage only).%s",
				aws.ToTime(v.CreateTime).Format("2006-01-02"), env.DaysSince(aws.ToTime(v.CreateTime)), size, volType, prices.EBSGBMonth[volType], priceNote(exact))
			f.Recommendation = "Confirm with the owner that the data is not needed. Take a final snapshot if in doubt, then delete the volume."
			f.FixCommand = fmt.Sprintf("aws ec2 create-snapshot --region %[1]s --volume-id %[2]s --description \"final snapshot before delete\"\naws ec2 delete-volume --region %[1]s --volume-id %[2]s", env.Region, id)
			findings = append(findings, f)
		}
	}
	return findings, nil
}
