package rules

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	s3ctltypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
	"github.com/minhhieu21193/cloudaudit/internal/fakeaws"
)

func bucketPAB(on bool) s3types.PublicAccessBlockConfiguration {
	return s3types.PublicAccessBlockConfiguration{BlockPublicAcls: aws.Bool(on), IgnorePublicAcls: aws.Bool(on), BlockPublicPolicy: aws.Bool(on), RestrictPublicBuckets: aws.Bool(on)}
}

func s3Buckets() *fakeaws.S3 {
	partial := bucketPAB(true)
	partial.BlockPublicPolicy = aws.Bool(false)
	return &fakeaws.S3{
		Buckets: []s3types.Bucket{
			{Name: aws.String("protected"), BucketRegion: aws.String("ap-northeast-1")},
			{Name: aws.String("no-config"), BucketRegion: aws.String("ap-northeast-1")},
			{Name: aws.String("partial"), BucketRegion: aws.String("us-east-1")},
		},
		PublicAccessBlocks: map[string]s3types.PublicAccessBlockConfiguration{"protected": bucketPAB(true), "partial": partial},
	}
}

func TestS3PublicAccessBlockAccountOn(t *testing.T) {
	on := &s3ctltypes.PublicAccessBlockConfiguration{BlockPublicAcls: aws.Bool(true), IgnorePublicAcls: aws.Bool(true), BlockPublicPolicy: aws.Bool(true), RestrictPublicBuckets: aws.Bool(true)}
	got, err := S3PublicAccessBlock{}.scan(context.Background(), s3Buckets(), &fakeaws.S3Control{AccountBlock: on}, testEnv(checks.GlobalRegion))
	if err != nil || len(got) != 0 {
		t.Fatalf("account fully blocked: got %+v, err %v", got, err)
	}
}

func TestS3PublicAccessBlockAccountMissing(t *testing.T) {
	got, err := S3PublicAccessBlock{}.scan(context.Background(), s3Buckets(), &fakeaws.S3Control{}, testEnv(checks.GlobalRegion))
	if err != nil {
		t.Fatal(err)
	}
	m := byResource(t, got)
	if len(m) != 3 {
		t.Fatalf("got %v, want account + no-config + partial", m)
	}
	acct := m["account/123456789012"]
	if acct.Severity != checks.SeverityHigh || !strings.Contains(acct.FixCommand, "s3control put-public-access-block --account-id 123456789012") {
		t.Errorf("account finding = %+v", acct)
	}
	if !strings.Contains(m["partial"].Evidence, "settings off (bucket and account combined): BlockPublicPolicy.") {
		t.Errorf("partial evidence = %q", m["partial"].Evidence)
	}
	if m["no-config"].Severity != checks.SeverityMedium {
		t.Errorf("no-config = %+v", m["no-config"])
	}
}

func TestS3PublicAccessBlockAccountPartialCoversBuckets(t *testing.T) {
	// Account blocks everything except BlockPublicPolicy; the "partial"
	// bucket is missing the same setting, so it is still exposed, while
	// "no-config" is exposed through the same gap.
	acct := &s3ctltypes.PublicAccessBlockConfiguration{BlockPublicAcls: aws.Bool(true), IgnorePublicAcls: aws.Bool(true), BlockPublicPolicy: aws.Bool(false), RestrictPublicBuckets: aws.Bool(true)}
	got, err := S3PublicAccessBlock{}.scan(context.Background(), s3Buckets(), &fakeaws.S3Control{AccountBlock: acct}, testEnv(checks.GlobalRegion))
	if err != nil {
		t.Fatal(err)
	}
	m := byResource(t, got)
	if _, ok := m["protected"]; ok || len(m) != 3 {
		t.Fatalf("got %v", m)
	}
	if !strings.HasSuffix(m["no-config"].Evidence, ": BlockPublicPolicy.") {
		t.Errorf("no-config evidence = %q", m["no-config"].Evidence)
	}
}

func TestS3PublicAccessBlockNeedsAccountID(t *testing.T) {
	env := testEnv(checks.GlobalRegion)
	env.AccountID = ""
	if _, err := (S3PublicAccessBlock{}).scan(context.Background(), s3Buckets(), &fakeaws.S3Control{}, env); err == nil {
		t.Fatal("expected error without account ID")
	}
}
