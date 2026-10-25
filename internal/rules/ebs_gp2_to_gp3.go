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

// gp3 gives 3,000 IOPS at no extra charge; gp2 gives 3 IOPS per GiB, so a gp2
// volume above this size has a higher baseline than gp3 without add-ons.
const gp2BaselineAboveGP3GiB = 1000

// EBSGP2ToGP3 flags in-use gp2 volumes. gp3 is about 20% cheaper per GiB and
// the change is an online ModifyVolume.
type EBSGP2ToGP3 struct{}

func (EBSGP2ToGP3) Meta() checks.Meta {
	return checks.Meta{
		ID:       "ebs-gp2-to-gp3",
		Name:     "gp2 volumes that can move to gp3",
		Category: checks.CategoryCost,
		DocsURL:  "https://docs.aws.amazon.com/ebs/latest/userguide/requesting-ebs-volume-modifications.html",
	}
}

type ebsGP2API interface {
	awsapi.DescribeVolumesAPI
	awsapi.DescribeInstancesAPI
}

func (c EBSGP2ToGP3) Run(ctx context.Context, env *checks.Env) ([]checks.Finding, error) {
	return c.scan(ctx, env.Clients.EC2, env)
}

func (c EBSGP2ToGP3) scan(ctx context.Context, api ebsGP2API, env *checks.Env) ([]checks.Finding, error) {
	// Volumes on long-stopped instances are already counted in full by
	// ec2-stopped, and unattached ones by ebs-unattached; skip both so the
	// report total does not double count.
	stopped, err := longStoppedInstances(ctx, api, env)
	if err != nil {
		return nil, err
	}
	skip := map[string]bool{}
	for _, s := range stopped {
		for _, vid := range s.volumeIDs {
			skip[vid] = true
		}
	}

	prices, exact := pricing.For(env.Region)
	delta := prices.EBSGBMonth["gp2"] - prices.EBSGBMonth["gp3"]
	meta := c.Meta()
	var findings []checks.Finding

	pages := ec2.NewDescribeVolumesPaginator(api, &ec2.DescribeVolumesInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("volume-type"), Values: []string{"gp2"}},
			{Name: aws.String("status"), Values: []string{"in-use"}},
		},
	})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe volumes: %w", err)
		}
		for _, v := range page.Volumes {
			id := aws.ToString(v.VolumeId)
			if skip[id] {
				continue
			}
			size := aws.ToInt32(v.Size)
			savings := delta * float64(size)
			attachedTo := ""
			if len(v.Attachments) > 0 {
				attachedTo = aws.ToString(v.Attachments[0].InstanceId)
			}

			f := meta.NewFinding(env, id)
			f.Title = fmt.Sprintf("gp2 volume %s (%d GiB) can move to gp3", withName(id, ec2Name(v.Tags)), size)
			f.Severity = costSeverity(savings)
			f.EstMonthlyUSD = savings
			f.Evidence = fmt.Sprintf("In use by %s. gp2 $%.3f vs gp3 $%.3f per GB-month.%s",
				attachedTo, prices.EBSGBMonth["gp2"], prices.EBSGBMonth["gp3"], priceNote(exact))
			f.Recommendation = "Modify the volume to gp3. The change is online and needs no downtime."
			if size > gp2BaselineAboveGP3GiB {
				f.Evidence += fmt.Sprintf(" At %d GiB the gp2 baseline is %d IOPS; provision gp3 IOPS to match, which reduces the saving.", size, 3*size)
				f.Recommendation += " Check CloudWatch VolumeReadOps/VolumeWriteOps first and provision gp3 IOPS/throughput to match real usage."
			}
			f.FixCommand = fmt.Sprintf("aws ec2 modify-volume --region %s --volume-id %s --volume-type gp3", env.Region, id)
			findings = append(findings, f)
		}
	}
	return findings, nil
}
