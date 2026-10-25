package rules

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type fakeVolumes struct {
	pages  [][]ec2types.Volume
	err    error
	inputs []*ec2.DescribeVolumesInput
}

func (f *fakeVolumes) DescribeVolumes(_ context.Context, in *ec2.DescribeVolumesInput, _ ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	f.inputs = append(f.inputs, in)
	if f.err != nil {
		return nil, f.err
	}
	i := 0
	if in.NextToken != nil {
		i = len(aws.ToString(in.NextToken))
	}
	out := &ec2.DescribeVolumesOutput{Volumes: f.pages[i]}
	if i+1 < len(f.pages) {
		out.NextToken = aws.String(strings.Repeat("x", i+1))
	}
	return out, nil
}

func TestEBSUnattached(t *testing.T) {
	fake := &fakeVolumes{pages: [][]ec2types.Volume{
		{{VolumeId: aws.String("vol-a"), Size: aws.Int32(500), VolumeType: ec2types.VolumeTypeGp2, CreateTime: aws.Time(daysAgo(200)),
			Tags: []ec2types.Tag{{Key: aws.String("Name"), Value: aws.String("old-db-data")}}}},
		{{VolumeId: aws.String("vol-b"), Size: aws.Int32(20), VolumeType: ec2types.VolumeTypeGp3, CreateTime: aws.Time(daysAgo(3))}},
	}}

	got, err := EBSUnattached{}.scan(context.Background(), fake, testEnv("ap-northeast-1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fake.inputs) != 2 {
		t.Fatalf("expected 2 paginated calls, got %d", len(fake.inputs))
	}
	filter := fake.inputs[0].Filters[0]
	if aws.ToString(filter.Name) != "status" || filter.Values[0] != "available" {
		t.Errorf("unexpected filter %+v", filter)
	}

	m := byResource(t, got)
	a := m["vol-a"]
	approxUSD(t, a.EstMonthlyUSD, 60) // 500 GiB x $0.12 gp2 in ap-northeast-1
	if a.Severity.String() != "MEDIUM" || !strings.Contains(a.Title, "old-db-data") {
		t.Errorf("vol-a = %+v", a)
	}
	if !strings.Contains(a.FixCommand, "delete-volume --region ap-northeast-1 --volume-id vol-a") {
		t.Errorf("fix command %q", a.FixCommand)
	}
	approxUSD(t, m["vol-b"].EstMonthlyUSD, 1.92) // 20 GiB x $0.096 gp3
}

func TestEBSUnattachedUnknownRegionNotesFallback(t *testing.T) {
	fake := &fakeVolumes{pages: [][]ec2types.Volume{{{VolumeId: aws.String("vol-a"), Size: aws.Int32(10), VolumeType: ec2types.VolumeTypeGp3, CreateTime: aws.Time(daysAgo(1))}}}}
	got, err := EBSUnattached{}.scan(context.Background(), fake, testEnv("me-central-1"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got[0].Evidence, "us-east-1 rates") {
		t.Errorf("evidence should mention the fallback price: %q", got[0].Evidence)
	}
}

func TestEBSUnattachedError(t *testing.T) {
	_, err := EBSUnattached{}.scan(context.Background(), &fakeVolumes{err: errors.New("AccessDenied")}, testEnv("us-east-1"))
	if err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("err = %v", err)
	}
}
