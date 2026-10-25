package rules

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
	"github.com/minhhieu21193/cloudaudit/internal/fakeaws"
)

func iamUser(name string) iamtypes.User {
	return iamtypes.User{UserName: aws.String(name), Arn: aws.String("arn:aws:iam::123456789012:user/" + name), CreateDate: aws.Time(daysAgo(500))}
}

func TestIAMUserNoMFA(t *testing.T) {
	alice, bob, ci, carol := iamUser("alice"), iamUser("bob"), iamUser("ci-deploy"), iamUser("carol")
	alice.PasswordLastUsed = aws.Time(daysAgo(2))
	fake := &fakeaws.IAM{
		Users:         []iamtypes.User{alice, bob, ci, carol},
		LoginProfiles: map[string]time.Time{"alice": daysAgo(400), "bob": daysAgo(300), "carol": daysAgo(10)},
		MFADevices:    map[string][]iamtypes.MFADevice{"carol": {{SerialNumber: aws.String("arn:aws:iam::123456789012:mfa/carol")}}},
	}
	got, err := IAMUserNoMFA{}.scan(context.Background(), fake, testEnv(checks.GlobalRegion))
	if err != nil {
		t.Fatal(err)
	}
	m := byResource(t, got)
	if len(m) != 2 {
		t.Fatalf("got %v, want alice and bob (ci-deploy has no console, carol has MFA)", m)
	}
	a := m["arn:aws:iam::123456789012:user/alice"]
	if a.Severity != checks.SeverityHigh || !strings.Contains(a.Evidence, "(2 days ago)") || a.Region != checks.GlobalRegion {
		t.Errorf("alice = %+v", a)
	}
	if !strings.Contains(m["arn:aws:iam::123456789012:user/bob"].Evidence, "last console sign-in never") {
		t.Errorf("bob evidence = %q", m["arn:aws:iam::123456789012:user/bob"].Evidence)
	}
}

func TestIAMUserNoMFAError(t *testing.T) {
	if _, err := (IAMUserNoMFA{}).scan(context.Background(), &fakeaws.IAM{Err: errors.New("AccessDenied")}, testEnv(checks.GlobalRegion)); err == nil {
		t.Fatal("expected error")
	}
}
