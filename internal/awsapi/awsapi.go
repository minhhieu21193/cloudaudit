// Package awsapi declares the narrow, read-only slices of the AWS SDK clients
// that cloudaudit uses. Each rule depends only on the operations it calls, so
// it can be unit-tested with a small fake, and the demo mode can stand in for
// AWS entirely. No interface here exposes a mutating operation.
package awsapi

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// EC2

type DescribeRegionsAPI interface {
	DescribeRegions(context.Context, *ec2.DescribeRegionsInput, ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
}

type DescribeVolumesAPI interface {
	DescribeVolumes(context.Context, *ec2.DescribeVolumesInput, ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
}

type DescribeAddressesAPI interface {
	DescribeAddresses(context.Context, *ec2.DescribeAddressesInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error)
}

type DescribeSnapshotsAPI interface {
	DescribeSnapshots(context.Context, *ec2.DescribeSnapshotsInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
}

type DescribeImagesAPI interface {
	DescribeImages(context.Context, *ec2.DescribeImagesInput, ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error)
}

type DescribeInstancesAPI interface {
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
}

type DescribeNatGatewaysAPI interface {
	DescribeNatGateways(context.Context, *ec2.DescribeNatGatewaysInput, ...func(*ec2.Options)) (*ec2.DescribeNatGatewaysOutput, error)
}

type DescribeSecurityGroupsAPI interface {
	DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
}

type GetEbsEncryptionByDefaultAPI interface {
	GetEbsEncryptionByDefault(context.Context, *ec2.GetEbsEncryptionByDefaultInput, ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error)
}

type EC2 interface {
	DescribeRegionsAPI
	DescribeVolumesAPI
	DescribeAddressesAPI
	DescribeSnapshotsAPI
	DescribeImagesAPI
	DescribeInstancesAPI
	DescribeNatGatewaysAPI
	DescribeSecurityGroupsAPI
	GetEbsEncryptionByDefaultAPI
}

// CloudWatch

type GetMetricStatisticsAPI interface {
	GetMetricStatistics(context.Context, *cloudwatch.GetMetricStatisticsInput, ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error)
}

type CloudWatch interface {
	GetMetricStatisticsAPI
}

// Elastic Load Balancing v2

type DescribeLoadBalancersAPI interface {
	DescribeLoadBalancers(context.Context, *elbv2.DescribeLoadBalancersInput, ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error)
}

type DescribeTargetGroupsAPI interface {
	DescribeTargetGroups(context.Context, *elbv2.DescribeTargetGroupsInput, ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupsOutput, error)
}

type DescribeTargetHealthAPI interface {
	DescribeTargetHealth(context.Context, *elbv2.DescribeTargetHealthInput, ...func(*elbv2.Options)) (*elbv2.DescribeTargetHealthOutput, error)
}

type ELBv2 interface {
	DescribeLoadBalancersAPI
	DescribeTargetGroupsAPI
	DescribeTargetHealthAPI
}

// S3

type ListBucketsAPI interface {
	ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
}

type GetBucketPublicAccessBlockAPI interface {
	GetPublicAccessBlock(context.Context, *s3.GetPublicAccessBlockInput, ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
}

type S3 interface {
	ListBucketsAPI
	GetBucketPublicAccessBlockAPI
}

type GetAccountPublicAccessBlockAPI interface {
	GetPublicAccessBlock(context.Context, *s3control.GetPublicAccessBlockInput, ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error)
}

type S3Control interface {
	GetAccountPublicAccessBlockAPI
}

// IAM

type ListUsersAPI interface {
	ListUsers(context.Context, *iam.ListUsersInput, ...func(*iam.Options)) (*iam.ListUsersOutput, error)
}

type GetLoginProfileAPI interface {
	GetLoginProfile(context.Context, *iam.GetLoginProfileInput, ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error)
}

type ListMFADevicesAPI interface {
	ListMFADevices(context.Context, *iam.ListMFADevicesInput, ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error)
}

type ListAccessKeysAPI interface {
	ListAccessKeys(context.Context, *iam.ListAccessKeysInput, ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
}

type GetAccessKeyLastUsedAPI interface {
	GetAccessKeyLastUsed(context.Context, *iam.GetAccessKeyLastUsedInput, ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error)
}

type GetAccountSummaryAPI interface {
	GetAccountSummary(context.Context, *iam.GetAccountSummaryInput, ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error)
}

type IAM interface {
	ListUsersAPI
	GetLoginProfileAPI
	ListMFADevicesAPI
	ListAccessKeysAPI
	GetAccessKeyLastUsedAPI
	GetAccountSummaryAPI
}

// RDS

type DescribeDBInstancesAPI interface {
	DescribeDBInstances(context.Context, *rds.DescribeDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
}

type RDS interface {
	DescribeDBInstancesAPI
}

// CloudTrail

type DescribeTrailsAPI interface {
	DescribeTrails(context.Context, *cloudtrail.DescribeTrailsInput, ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error)
}

type GetTrailStatusAPI interface {
	GetTrailStatus(context.Context, *cloudtrail.GetTrailStatusInput, ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error)
}

type CloudTrail interface {
	DescribeTrailsAPI
	GetTrailStatusAPI
}

// STS

type GetCallerIdentityAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type STS interface {
	GetCallerIdentityAPI
}

// Clients bundles the per-region service clients handed to each check.
type Clients struct {
	EC2        EC2
	CloudWatch CloudWatch
	ELBv2      ELBv2
	S3         S3
	S3Control  S3Control
	IAM        IAM
	RDS        RDS
	CloudTrail CloudTrail
}

// The real SDK clients must satisfy the interfaces above.
var (
	_ EC2        = (*ec2.Client)(nil)
	_ CloudWatch = (*cloudwatch.Client)(nil)
	_ ELBv2      = (*elbv2.Client)(nil)
	_ S3         = (*s3.Client)(nil)
	_ S3Control  = (*s3control.Client)(nil)
	_ IAM        = (*iam.Client)(nil)
	_ RDS        = (*rds.Client)(nil)
	_ CloudTrail = (*cloudtrail.Client)(nil)
	_ STS        = (*sts.Client)(nil)
)
