package rules

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/minhhieu21193/cloudaudit/internal/fakeaws"
)

func TestEIPUnassociated(t *testing.T) {
	fake := &fakeaws.EC2{Addresses: []ec2types.Address{
		{AllocationId: aws.String("eipalloc-idle"), PublicIp: aws.String("203.0.113.10")},
		{AllocationId: aws.String("eipalloc-used"), PublicIp: aws.String("203.0.113.11"), AssociationId: aws.String("eipassoc-1")},
		{AllocationId: aws.String("eipalloc-eni"), PublicIp: aws.String("203.0.113.12"), NetworkInterfaceId: aws.String("eni-1")},
		{AllocationId: aws.String("eipalloc-svc"), PublicIp: aws.String("203.0.113.13"), ServiceManaged: ec2types.ServiceManagedAlb},
	}}
	got, err := EIPUnassociated{}.scan(context.Background(), fake, testEnv("us-east-1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ResourceID != "eipalloc-idle" {
		t.Fatalf("got %+v, want only eipalloc-idle", got)
	}
	approxUSD(t, got[0].EstMonthlyUSD, 3.65)
	if !strings.Contains(got[0].FixCommand, "release-address --region us-east-1 --allocation-id eipalloc-idle") {
		t.Errorf("fix = %q", got[0].FixCommand)
	}
}
