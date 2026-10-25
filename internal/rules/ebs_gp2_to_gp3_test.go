package rules

import (
	"context"
	"strings"
	"testing"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/minhhieu21193/cloudaudit/internal/fakeaws"
)

func TestEBSGP2ToGP3(t *testing.T) {
	old := "User initiated (" + daysAgo(90).Format("2006-01-02 15:04:05") + " GMT)"
	fake := &fakeaws.EC2{
		Instances: []ec2types.Instance{newStoppedInstance("i-stopped", old, "vol-on-stopped")},
		Volumes: []ec2types.Volume{
			vol("vol-small", 100, ec2types.VolumeTypeGp2, ec2types.VolumeStateInUse, "i-web"),
			vol("vol-big", 2000, ec2types.VolumeTypeGp2, ec2types.VolumeStateInUse, "i-db"),
			vol("vol-gp3", 100, ec2types.VolumeTypeGp3, ec2types.VolumeStateInUse, "i-web"),
			vol("vol-loose", 100, ec2types.VolumeTypeGp2, ec2types.VolumeStateAvailable, ""),
			vol("vol-on-stopped", 100, ec2types.VolumeTypeGp2, ec2types.VolumeStateInUse, "i-stopped"),
		},
	}
	got, err := EBSGP2ToGP3{}.scan(context.Background(), fake, testEnv("ap-southeast-1"))
	if err != nil {
		t.Fatal(err)
	}
	m := byResource(t, got)
	if len(m) != 2 {
		t.Fatalf("got %v, want vol-small and vol-big only", m)
	}
	approxUSD(t, m["vol-small"].EstMonthlyUSD, 100*(0.12-0.096))
	if !strings.Contains(m["vol-big"].Evidence, "6000 IOPS") {
		t.Errorf("large volume should mention the IOPS caveat: %q", m["vol-big"].Evidence)
	}
	if strings.Contains(m["vol-small"].Evidence, "IOPS") {
		t.Errorf("small volume should not mention IOPS: %q", m["vol-small"].Evidence)
	}
	if !strings.Contains(m["vol-small"].FixCommand, "--volume-type gp3") {
		t.Errorf("fix = %q", m["vol-small"].FixCommand)
	}
}
