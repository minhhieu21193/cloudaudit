package rules

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
	"github.com/minhhieu21193/cloudaudit/internal/pricing"
)

// EC2Stopped flags instances stopped for longer than Config.StoppedMinDays.
// Compute is free while stopped, but attached EBS volumes are still billed.
type EC2Stopped struct{}

func (EC2Stopped) Meta() checks.Meta {
	return checks.Meta{
		ID:       "ec2-stopped",
		Name:     "Long-stopped EC2 instances",
		Category: checks.CategoryCost,
		DocsURL:  "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Stop_Start.html",
	}
}

type ec2StoppedAPI interface {
	awsapi.DescribeInstancesAPI
	awsapi.DescribeVolumesAPI
}

func (c EC2Stopped) Run(ctx context.Context, env *checks.Env) ([]checks.Finding, error) {
	return c.scan(ctx, env.Clients.EC2, env)
}

func (c EC2Stopped) scan(ctx context.Context, api ec2StoppedAPI, env *checks.Env) ([]checks.Finding, error) {
	stopped, err := longStoppedInstances(ctx, api, env)
	if err != nil {
		return nil, err
	}
	var volumeIDs []string
	for _, s := range stopped {
		volumeIDs = append(volumeIDs, s.volumeIDs...)
	}
	volumes, err := volumesByID(ctx, api, volumeIDs)
	if err != nil {
		return nil, err
	}

	prices, exact := pricing.For(env.Region)
	meta := c.Meta()
	var findings []checks.Finding
	for _, s := range stopped {
		var cost float64
		var totalGiB int32
		for _, vid := range s.volumeIDs {
			if v, ok := volumes[vid]; ok {
				cost += prices.EBSMonthly(string(v.VolumeType), aws.ToInt32(v.Size))
				totalGiB += aws.ToInt32(v.Size)
			}
		}
		f := meta.NewFinding(env, s.id)
		f.Title = fmt.Sprintf("Instance %s stopped for %d days", withName(s.id, s.name), s.days)
		f.Severity = costSeverity(cost)
		f.EstMonthlyUSD = cost
		f.Evidence = fmt.Sprintf("%s stopped since %s (%d days, threshold %d). %d attached EBS volume(s), %d GiB in total, still billed.%s",
			s.instanceType, s.since.Format("2006-01-02"), s.days, env.Config.StoppedMinDays, len(s.volumeIDs), totalGiB, priceNote(exact))
		f.Recommendation = "If the instance is no longer needed, create an AMI as a backup and terminate it. Otherwise snapshot and delete the data volumes it does not need."
		f.FixCommand = fmt.Sprintf("aws ec2 create-image --region %[1]s --instance-id %[2]s --name \"%[2]s-final-backup\"\naws ec2 terminate-instances --region %[1]s --instance-ids %[2]s", env.Region, s.id)
		findings = append(findings, f)
	}
	return findings, nil
}

type stoppedInstance struct {
	id           string
	name         string
	instanceType string
	since        time.Time
	days         int
	volumeIDs    []string
}

// stopTimeRE matches the timestamp EC2 puts in StateTransitionReason, e.g.
// "User initiated (2026-01-15 10:30:00 GMT)".
var stopTimeRE = regexp.MustCompile(`\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) GMT\)`)

func parseStopTime(reason string) (time.Time, bool) {
	m := stopTimeRE.FindStringSubmatch(reason)
	if m == nil {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02 15:04:05", m[1])
	return t.UTC(), err == nil
}

// longStoppedInstances returns instances stopped for at least
// Config.StoppedMinDays. Instances whose stop time cannot be determined are
// skipped rather than guessed.
func longStoppedInstances(ctx context.Context, api awsapi.DescribeInstancesAPI, env *checks.Env) ([]stoppedInstance, error) {
	var out []stoppedInstance
	pages := ec2.NewDescribeInstancesPaginator(api, &ec2.DescribeInstancesInput{
		Filters: []ec2types.Filter{{Name: aws.String("instance-state-name"), Values: []string{"stopped"}}},
	})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe instances: %w", err)
		}
		for _, r := range page.Reservations {
			for _, inst := range r.Instances {
				since, ok := parseStopTime(aws.ToString(inst.StateTransitionReason))
				if !ok {
					continue
				}
				days := env.DaysSince(since)
				if days < env.Config.StoppedMinDays {
					continue
				}
				s := stoppedInstance{
					id:           aws.ToString(inst.InstanceId),
					name:         ec2Name(inst.Tags),
					instanceType: string(inst.InstanceType),
					since:        since,
					days:         days,
				}
				for _, bdm := range inst.BlockDeviceMappings {
					if bdm.Ebs != nil && bdm.Ebs.VolumeId != nil {
						s.volumeIDs = append(s.volumeIDs, *bdm.Ebs.VolumeId)
					}
				}
				out = append(out, s)
			}
		}
	}
	return out, nil
}

// volumeIDChunk keeps each DescribeVolumes filter well under the EC2 limit
// on filter values.
const volumeIDChunk = 100

func volumesByID(ctx context.Context, api awsapi.DescribeVolumesAPI, ids []string) (map[string]ec2types.Volume, error) {
	out := map[string]ec2types.Volume{}
	for chunk := range slices.Chunk(ids, volumeIDChunk) {
		pages := ec2.NewDescribeVolumesPaginator(api, &ec2.DescribeVolumesInput{
			Filters: []ec2types.Filter{{Name: aws.String("volume-id"), Values: chunk}},
		})
		for pages.HasMorePages() {
			page, err := pages.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("describe volumes %s: %w", strings.Join(chunk, ","), err)
			}
			for _, v := range page.Volumes {
				out[aws.ToString(v.VolumeId)] = v
			}
		}
	}
	return out, nil
}
