package ebs

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	awsclient "github.com/minhhieu21193/cloudaudit/internal/aws"
	check "github.com/minhhieu21193/cloudaudit/internal/checks"
)

type CheckOrphanedEBS struct{}

func (*CheckOrphanedEBS) Run(ctx context.Context, client *awsclient.Client) ([]check.Finding, error) {
	filterEBS := &ec2.DescribeVolumesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("status"),
				Values: []string{"available"},
			},
		},
	}
	orphansVolumes, err := client.Ec2.DescribeVolumes(ctx, filterEBS)

	if err != nil {
		return nil, err
	}
	result := []check.Finding{}

	for _, vol := range orphansVolumes.Volumes {
		saving := float64(*vol.Size) * 0.1
		result = append(result, check.Finding{
			Title:          fmt.Sprintf("Orphaned EBS volume %s", *vol.VolumeId),
			Severity:       "HIGH",
			Description:    "Idle EBS volume not attached to any instance",
			MonthlySavings: saving,
			Recommendation: "xóa hoặc snapshot rồi xóa",
			FixCommand:     fmt.Sprintf("aws ec2 delete-volume --volume-id %s", *vol.VolumeId),
		})

	}
	return result, nil
}
