package fakeaws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
)

var _ awsapi.CloudTrail = (*CloudTrail)(nil)

type CloudTrail struct {
	Trails []cttypes.Trail
	// Logging is keyed by trail ARN.
	Logging map[string]bool
	Err     error
}

func (f *CloudTrail) DescribeTrails(context.Context, *cloudtrail.DescribeTrailsInput, ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return &cloudtrail.DescribeTrailsOutput{TrailList: f.Trails}, nil
}

func (f *CloudTrail) GetTrailStatus(_ context.Context, in *cloudtrail.GetTrailStatusInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	logging, ok := f.Logging[aws.ToString(in.Name)]
	if !ok {
		return nil, fmt.Errorf("fakeaws: GetTrailStatus wants a trail ARN, got %q", aws.ToString(in.Name))
	}
	return &cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(logging)}, nil
}
