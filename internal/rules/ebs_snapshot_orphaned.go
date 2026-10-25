package rules

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
	"github.com/minhhieu21193/cloudaudit/internal/pricing"
)

const bytesPerGiB = 1 << 30

// EBSSnapshotOrphaned flags snapshots older than Config.SnapshotMinAgeDays
// whose source volume no longer exists. Snapshots that back an AMI or are
// managed by AWS Backup are skipped: they have an owner process.
type EBSSnapshotOrphaned struct{}

func (EBSSnapshotOrphaned) Meta() checks.Meta {
	return checks.Meta{
		ID:       "ebs-snapshot-orphaned",
		Name:     "Old snapshots of deleted volumes",
		Category: checks.CategoryCost,
		DocsURL:  "https://docs.aws.amazon.com/ebs/latest/userguide/ebs-deleting-snapshot.html",
	}
}

type ebsSnapshotAPI interface {
	awsapi.DescribeSnapshotsAPI
	awsapi.DescribeVolumesAPI
	awsapi.DescribeImagesAPI
}

func (c EBSSnapshotOrphaned) Run(ctx context.Context, env *checks.Env) ([]checks.Finding, error) {
	return c.scan(ctx, env.Clients.EC2, env)
}

func (c EBSSnapshotOrphaned) scan(ctx context.Context, api ebsSnapshotAPI, env *checks.Env) ([]checks.Finding, error) {
	existing := map[string]bool{}
	volPages := ec2.NewDescribeVolumesPaginator(api, &ec2.DescribeVolumesInput{})
	for volPages.HasMorePages() {
		page, err := volPages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe volumes: %w", err)
		}
		for _, v := range page.Volumes {
			existing[aws.ToString(v.VolumeId)] = true
		}
	}

	usedByAMI := map[string]string{}
	imgPages := ec2.NewDescribeImagesPaginator(api, &ec2.DescribeImagesInput{Owners: []string{"self"}})
	for imgPages.HasMorePages() {
		page, err := imgPages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe images: %w", err)
		}
		for _, img := range page.Images {
			for _, bdm := range img.BlockDeviceMappings {
				if bdm.Ebs != nil && bdm.Ebs.SnapshotId != nil {
					usedByAMI[*bdm.Ebs.SnapshotId] = aws.ToString(img.ImageId)
				}
			}
		}
	}

	prices, exact := pricing.For(env.Region)
	meta := c.Meta()
	var findings []checks.Finding
	snapPages := ec2.NewDescribeSnapshotsPaginator(api, &ec2.DescribeSnapshotsInput{OwnerIds: []string{"self"}})
	for snapPages.HasMorePages() {
		page, err := snapPages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe snapshots: %w", err)
		}
		for _, s := range page.Snapshots {
			id := aws.ToString(s.SnapshotId)
			age := env.DaysSince(aws.ToTime(s.StartTime))
			source := aws.ToString(s.VolumeId)
			if age < env.Config.SnapshotMinAgeDays || existing[source] || usedByAMI[id] != "" || managedByBackup(s.Tags) {
				continue
			}

			size := aws.ToInt32(s.VolumeSize)
			sizeNote := fmt.Sprintf("Priced at the full source size of %d GiB, an upper bound: snapshots are incremental and may bill less.", size)
			cost := prices.SnapshotMonthly(size)
			if full := aws.ToInt64(s.FullSnapshotSizeInBytes); full > 0 {
				gib := float64(full) / bytesPerGiB
				cost = prices.SnapshotGBMonth * gib
				sizeNote = fmt.Sprintf("Full snapshot size %.1f GiB (upper bound; incremental billing may be lower).", gib)
			}

			f := meta.NewFinding(env, id)
			f.Title = fmt.Sprintf("Snapshot %s is %d days old and its volume is gone", displayName(id, ec2Name(s.Tags)), age)
			f.Severity = costSeverity(cost)
			f.EstMonthlyUSD = cost
			f.Evidence = fmt.Sprintf("Created %s from %s, which no longer exists. Not used by any AMI owned by this account. %s%s",
				aws.ToTime(s.StartTime).Format("2006-01-02"), sourceLabel(source), sizeNote, priceNote(exact))
			if desc := strings.TrimSpace(aws.ToString(s.Description)); desc != "" {
				f.Evidence += fmt.Sprintf(" Description: %q.", desc)
			}
			f.Recommendation = "Confirm no restore or compliance requirement depends on it, then delete it. To keep it cheaply, move it to the archive tier instead."
			f.FixCommand = fmt.Sprintf("aws ec2 delete-snapshot --region %s --snapshot-id %s", env.Region, id)
			findings = append(findings, f)
		}
	}
	return findings, nil
}

func sourceLabel(volumeID string) string {
	// CopySnapshot results carry this placeholder instead of a real volume.
	if volumeID == "" || volumeID == "vol-ffffffff" {
		return "a copied snapshot (no source volume)"
	}
	return "volume " + volumeID
}

func managedByBackup(tags []ec2types.Tag) bool {
	for _, t := range tags {
		if strings.HasPrefix(aws.ToString(t.Key), "aws:backup:") {
			return true
		}
	}
	return false
}
