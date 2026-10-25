package rules

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/minhhieu21193/cloudaudit/internal/fakeaws"
)

func TestEBSSnapshotOrphaned(t *testing.T) {
	snap := func(id, volumeID string, age int, sizeGiB int32, tags ...ec2types.Tag) ec2types.Snapshot {
		return ec2types.Snapshot{SnapshotId: aws.String(id), VolumeId: aws.String(volumeID), StartTime: aws.Time(daysAgo(age)), VolumeSize: aws.Int32(sizeGiB), Tags: tags}
	}
	full := snap("snap-full-size", "vol-deleted", 200, 100)
	full.FullSnapshotSizeInBytes = aws.Int64(20 << 30)

	fake := &fakeaws.EC2{
		Volumes: []ec2types.Volume{vol("vol-live", 50, ec2types.VolumeTypeGp3, ec2types.VolumeStateInUse, "i-1")},
		Images: []ec2types.Image{{ImageId: aws.String("ami-1"), BlockDeviceMappings: []ec2types.BlockDeviceMapping{
			{Ebs: &ec2types.EbsBlockDevice{SnapshotId: aws.String("snap-ami")}},
		}}},
		Snapshots: []ec2types.Snapshot{
			snap("snap-orphan", "vol-deleted", 365, 200),
			full,
			snap("snap-copy", "vol-ffffffff", 180, 10),
			snap("snap-live-source", "vol-live", 365, 50),
			snap("snap-young", "vol-deleted", 30, 200),
			snap("snap-ami", "vol-deleted", 365, 8),
			snap("snap-backup", "vol-deleted", 365, 100, ec2types.Tag{Key: aws.String("aws:backup:source-resource"), Value: aws.String("x")}),
		},
	}
	got, err := EBSSnapshotOrphaned{}.scan(context.Background(), fake, testEnv("us-east-1"))
	if err != nil {
		t.Fatal(err)
	}
	m := byResource(t, got)
	if len(m) != 3 {
		t.Fatalf("got %v, want snap-orphan, snap-full-size, snap-copy", m)
	}
	approxUSD(t, m["snap-orphan"].EstMonthlyUSD, 200*0.05)
	approxUSD(t, m["snap-full-size"].EstMonthlyUSD, 20*0.05)
	if !strings.Contains(m["snap-orphan"].Evidence, "upper bound") {
		t.Errorf("evidence should flag the upper-bound estimate: %q", m["snap-orphan"].Evidence)
	}
	if !strings.Contains(m["snap-copy"].Evidence, "copied snapshot") {
		t.Errorf("copy evidence = %q", m["snap-copy"].Evidence)
	}
}
