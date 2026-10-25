package rules

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/minhhieu21193/cloudaudit/internal/fakeaws"
)

func TestParseStopTime(t *testing.T) {
	ts, ok := parseStopTime("User initiated (2026-06-01 08:15:00 GMT)")
	if !ok || ts.Format("2006-01-02 15:04") != "2026-06-01 08:15" {
		t.Fatalf("parseStopTime = %v, %v", ts, ok)
	}
	if _, ok := parseStopTime("Server.SpotInstanceTermination"); ok {
		t.Fatal("expected no match without a timestamp")
	}
}

func TestEC2Stopped(t *testing.T) {
	old := "User initiated (" + daysAgo(120).Format("2006-01-02 15:04:05") + " GMT)"
	recent := "User initiated (" + daysAgo(5).Format("2006-01-02 15:04:05") + " GMT)"
	fake := &fakeaws.EC2{
		Instances: []ec2types.Instance{
			newStoppedInstance("i-old", old, "vol-root", "vol-data"),
			newStoppedInstance("i-recent", recent, "vol-other"),
			newStoppedInstance("i-unknown", "", "vol-x"),
			{InstanceId: aws.String("i-running"), State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning}},
		},
		Volumes: []ec2types.Volume{
			vol("vol-root", 30, ec2types.VolumeTypeGp3, ec2types.VolumeStateInUse, "i-old"),
			vol("vol-data", 500, ec2types.VolumeTypeGp2, ec2types.VolumeStateInUse, "i-old"),
			vol("vol-other", 100, ec2types.VolumeTypeGp2, ec2types.VolumeStateInUse, "i-recent"),
		},
	}
	got, err := EC2Stopped{}.scan(context.Background(), fake, testEnv("us-east-1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ResourceID != "i-old" {
		t.Fatalf("got %+v, want only i-old", got)
	}
	approxUSD(t, got[0].EstMonthlyUSD, 30*0.08+500*0.10)
	if !strings.Contains(got[0].Evidence, "120 days") || !strings.Contains(got[0].Evidence, "530 GiB") {
		t.Errorf("evidence = %q", got[0].Evidence)
	}
}
