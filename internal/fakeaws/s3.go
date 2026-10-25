package fakeaws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3ctltypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	"github.com/aws/smithy-go"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
)

var (
	_ awsapi.S3        = (*S3)(nil)
	_ awsapi.S3Control = (*S3Control)(nil)
)

// errNoPublicAccessBlock is what S3 and S3 Control return when no Block
// Public Access configuration exists.
var errNoPublicAccessBlock = &smithy.GenericAPIError{
	Code:    "NoSuchPublicAccessBlockConfiguration",
	Message: "The public access block configuration was not found",
}

type S3 struct {
	Buckets []s3types.Bucket
	// PublicAccessBlocks is keyed by bucket name; a missing entry means the
	// bucket has no configuration.
	PublicAccessBlocks map[string]s3types.PublicAccessBlockConfiguration
	Err                error
}

func (f *S3) ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return &s3.ListBucketsOutput{Buckets: f.Buckets}, nil
}

func (f *S3) GetPublicAccessBlock(_ context.Context, in *s3.GetPublicAccessBlockInput, _ ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	cfg, ok := f.PublicAccessBlocks[aws.ToString(in.Bucket)]
	if !ok {
		return nil, errNoPublicAccessBlock
	}
	return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: &cfg}, nil
}

type S3Control struct {
	// AccountBlock is nil when the account has no configuration.
	AccountBlock *s3ctltypes.PublicAccessBlockConfiguration
	Err          error
}

func (f *S3Control) GetPublicAccessBlock(context.Context, *s3control.GetPublicAccessBlockInput, ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	if f.AccountBlock == nil {
		return nil, errNoPublicAccessBlock
	}
	return &s3control.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: f.AccountBlock}, nil
}
