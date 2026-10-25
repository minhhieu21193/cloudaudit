package rules

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
)

// RootAccount flags a root user that has access keys or no MFA, using
// GetAccountSummary.
type RootAccount struct{}

func (RootAccount) Meta() checks.Meta {
	return checks.Meta{
		ID:       "root-account",
		Name:     "Root user with access keys or without MFA",
		Category: checks.CategorySecurity,
		Global:   true,
		DocsURL:  "https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html",
	}
}

func (c RootAccount) Run(ctx context.Context, env *checks.Env) ([]checks.Finding, error) {
	return c.scan(ctx, env.Clients.IAM, env)
}

func (c RootAccount) scan(ctx context.Context, api awsapi.GetAccountSummaryAPI, env *checks.Env) ([]checks.Finding, error) {
	out, err := api.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, fmt.Errorf("get account summary: %w", err)
	}
	meta := c.Meta()
	var findings []checks.Finding
	if keys := out.SummaryMap["AccountAccessKeysPresent"]; keys > 0 {
		f := meta.NewFinding(env, "root/access-keys")
		f.Title = "Root user has access keys"
		f.Severity = checks.SeverityCritical
		f.Evidence = fmt.Sprintf("GetAccountSummary: AccountAccessKeysPresent=%d. Root keys cannot be limited by any IAM policy.", keys)
		f.Recommendation = "Sign in as the root user, check when each key was last used, move any automation to an IAM role, then delete the root access keys."
		findings = append(findings, f)
	}
	if out.SummaryMap["AccountMFAEnabled"] == 0 {
		f := meta.NewFinding(env, "root/mfa")
		f.Title = "Root user does not have MFA enabled"
		f.Severity = checks.SeverityCritical
		f.Evidence = "GetAccountSummary: AccountMFAEnabled=0. The root user can sign in with a password alone."
		f.Recommendation = "Sign in as the root user and assign an MFA device (a hardware key or passkey is best) under Security credentials. This needs the root password, so no CLI command is given."
		findings = append(findings, f)
	}
	return findings, nil
}
