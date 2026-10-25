package fakeaws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
)

var _ awsapi.IAM = (*IAM)(nil)

type IAM struct {
	Users []iamtypes.User
	// LoginProfiles holds the console-password creation time per user;
	// users without an entry have no console access.
	LoginProfiles map[string]time.Time
	MFADevices    map[string][]iamtypes.MFADevice
	AccessKeys    map[string][]iamtypes.AccessKeyMetadata
	// KeyLastUsed is keyed by access key ID; a missing key was never used.
	KeyLastUsed map[string]time.Time
	Summary     map[string]int32
	Err         error
}

func (f *IAM) ListUsers(context.Context, *iam.ListUsersInput, ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return &iam.ListUsersOutput{Users: f.Users}, nil
}

func (f *IAM) GetLoginProfile(_ context.Context, in *iam.GetLoginProfileInput, _ ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	created, ok := f.LoginProfiles[aws.ToString(in.UserName)]
	if !ok {
		return nil, &iamtypes.NoSuchEntityException{Message: aws.String("Login Profile for User " + aws.ToString(in.UserName) + " cannot be found.")}
	}
	return &iam.GetLoginProfileOutput{LoginProfile: &iamtypes.LoginProfile{UserName: in.UserName, CreateDate: aws.Time(created)}}, nil
}

func (f *IAM) ListMFADevices(_ context.Context, in *iam.ListMFADevicesInput, _ ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return &iam.ListMFADevicesOutput{MFADevices: f.MFADevices[aws.ToString(in.UserName)]}, nil
}

func (f *IAM) ListAccessKeys(_ context.Context, in *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return &iam.ListAccessKeysOutput{AccessKeyMetadata: f.AccessKeys[aws.ToString(in.UserName)]}, nil
}

func (f *IAM) GetAccessKeyLastUsed(_ context.Context, in *iam.GetAccessKeyLastUsedInput, _ ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	out := &iam.GetAccessKeyLastUsedOutput{AccessKeyLastUsed: &iamtypes.AccessKeyLastUsed{Region: aws.String("N/A"), ServiceName: aws.String("N/A")}}
	if t, ok := f.KeyLastUsed[aws.ToString(in.AccessKeyId)]; ok {
		out.AccessKeyLastUsed = &iamtypes.AccessKeyLastUsed{LastUsedDate: aws.Time(t), Region: aws.String("us-east-1"), ServiceName: aws.String("s3")}
	}
	return out, nil
}

func (f *IAM) GetAccountSummary(context.Context, *iam.GetAccountSummaryInput, ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return &iam.GetAccountSummaryOutput{SummaryMap: f.Summary}, nil
}
