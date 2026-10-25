package fakeaws

import (
	"context"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
)

var _ awsapi.ELBv2 = (*ELBv2)(nil)

type ELBv2 struct {
	LoadBalancers []elbtypes.LoadBalancer
	TargetGroups  []elbtypes.TargetGroup
	// TargetHealth is keyed by target group ARN.
	TargetHealth map[string][]elbtypes.TargetHealthDescription
	Err          error
}

func (f *ELBv2) DescribeLoadBalancers(context.Context, *elbv2.DescribeLoadBalancersInput, ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return &elbv2.DescribeLoadBalancersOutput{LoadBalancers: f.LoadBalancers}, nil
}

func (f *ELBv2) DescribeTargetGroups(_ context.Context, in *elbv2.DescribeTargetGroupsInput, _ ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupsOutput, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	out := &elbv2.DescribeTargetGroupsOutput{}
	for _, tg := range f.TargetGroups {
		if in.LoadBalancerArn == nil || slices.Contains(tg.LoadBalancerArns, *in.LoadBalancerArn) {
			out.TargetGroups = append(out.TargetGroups, tg)
		}
	}
	return out, nil
}

func (f *ELBv2) DescribeTargetHealth(_ context.Context, in *elbv2.DescribeTargetHealthInput, _ ...func(*elbv2.Options)) (*elbv2.DescribeTargetHealthOutput, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return &elbv2.DescribeTargetHealthOutput{TargetHealthDescriptions: f.TargetHealth[aws.ToString(in.TargetGroupArn)]}, nil
}
