package awsclient

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type fakeSTS struct{ err error }

func (f fakeSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &sts.GetCallerIdentityOutput{Account: aws.String("123456789012")}, nil
}

type fakeRegions struct{ in *ec2.DescribeRegionsInput }

func (f *fakeRegions) DescribeRegions(_ context.Context, in *ec2.DescribeRegionsInput, _ ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	f.in = in
	return &ec2.DescribeRegionsOutput{Regions: []ec2types.Region{{RegionName: aws.String("us-west-2")}, {RegionName: aws.String("ap-northeast-1")}}}, nil
}

func TestAccountID(t *testing.T) {
	id, err := accountID(context.Background(), fakeSTS{})
	if err != nil || id != "123456789012" {
		t.Fatalf("accountID = %q, %v", id, err)
	}
	if _, err := accountID(context.Background(), fakeSTS{err: errors.New("ExpiredToken")}); err == nil || !strings.Contains(err.Error(), "ExpiredToken") {
		t.Fatalf("err = %v", err)
	}
}

func TestEnabledRegionsSortedAndOptedInOnly(t *testing.T) {
	f := &fakeRegions{}
	got, err := enabledRegions(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "ap-northeast-1,us-west-2" {
		t.Errorf("regions = %v", got)
	}
	if aws.ToBool(f.in.AllRegions) {
		t.Error("must not request opted-out regions")
	}
}

func TestLoadRejectsExternalIDWithoutRole(t *testing.T) {
	// Point the SDK at empty config files so the test never reads real
	// credentials or contacts AWS.
	t.Setenv("AWS_CONFIG_FILE", "/dev/null")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	if _, err := Load(context.Background(), Options{ExternalID: "x"}); err == nil || !strings.Contains(err.Error(), "--role-arn") {
		t.Fatalf("err = %v", err)
	}
	s, err := Load(context.Background(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if s.DefaultRegion() != fallbackRegion {
		t.Errorf("DefaultRegion = %q, want %q", s.DefaultRegion(), fallbackRegion)
	}
}
