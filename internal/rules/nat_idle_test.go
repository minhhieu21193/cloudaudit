package rules

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/minhhieu21193/cloudaudit/internal/fakeaws"
)

func TestNATIdle(t *testing.T) {
	nat := func(id string, ageDays int, state ec2types.NatGatewayState) ec2types.NatGateway {
		return ec2types.NatGateway{
			NatGatewayId: aws.String(id), State: state, CreateTime: aws.Time(daysAgo(ageDays)),
			VpcId: aws.String("vpc-1"), SubnetId: aws.String("subnet-1"),
			NatGatewayAddresses: []ec2types.NatGatewayAddress{{AllocationId: aws.String("eipalloc-" + id)}},
		}
	}
	ec2fake := &fakeaws.EC2{NatGateways: []ec2types.NatGateway{
		nat("nat-idle", 300, ec2types.NatGatewayStateAvailable),
		nat("nat-busy", 300, ec2types.NatGatewayStateAvailable),
		nat("nat-new", 3, ec2types.NatGatewayStateAvailable),
		nat("nat-deleted", 300, ec2types.NatGatewayStateDeleted),
	}}
	cw := &fakeaws.CloudWatch{Sums: map[fakeaws.MetricKey][]float64{
		{Namespace: "AWS/NATGateway", Metric: "BytesOutToDestination", Dimension: "nat-idle"}: {1 << 20, 2 << 20},
		{Namespace: "AWS/NATGateway", Metric: "BytesOutToDestination", Dimension: "nat-busy"}: {5 << 30, 7 << 30},
	}}

	got, err := NATIdle{}.scan(context.Background(), ec2fake, cw, testEnv("ap-northeast-1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ResourceID != "nat-idle" {
		t.Fatalf("got %+v, want only nat-idle", got)
	}
	f := got[0]
	approxUSD(t, f.EstMonthlyUSD, 0.062*730)
	if !strings.Contains(f.Title, "3.0 MiB in 14 days") {
		t.Errorf("title = %q", f.Title)
	}
	if !strings.Contains(f.FixCommand, "delete-nat-gateway --region ap-northeast-1 --nat-gateway-id nat-idle") ||
		!strings.Contains(f.FixCommand, "eipalloc-nat-idle") {
		t.Errorf("fix = %q", f.FixCommand)
	}
}

func TestHumanBytes(t *testing.T) {
	for in, want := range map[float64]string{512: "512 B", 2048: "2.0 KiB", 3 << 20: "3.0 MiB", 1.5 * (1 << 30): "1.50 GiB"} {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%v) = %q, want %q", in, got, want)
		}
	}
}
