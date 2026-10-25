package rules

import (
	"context"
	"testing"

	"github.com/minhhieu21193/cloudaudit/internal/fakeaws"
)

func TestEBSEncryptionDefault(t *testing.T) {
	env := testEnv("ap-southeast-1")
	got, err := EBSEncryptionDefault{}.scan(context.Background(), &fakeaws.EC2{EBSEncryptionByDefault: false}, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].FixCommand != "aws ec2 enable-ebs-encryption-by-default --region ap-southeast-1" {
		t.Fatalf("got %+v", got)
	}
	got, err = EBSEncryptionDefault{}.scan(context.Background(), &fakeaws.EC2{EBSEncryptionByDefault: true}, env)
	if err != nil || len(got) != 0 {
		t.Fatalf("enabled: got %+v, err %v", got, err)
	}
}
