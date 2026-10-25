package rules

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
)

// IAMUserNoMFA flags IAM users who can sign in to the console without MFA.
type IAMUserNoMFA struct{}

func (IAMUserNoMFA) Meta() checks.Meta {
	return checks.Meta{
		ID:       "iam-user-no-mfa",
		Name:     "IAM console users without MFA",
		Category: checks.CategorySecurity,
		Global:   true,
		DocsURL:  "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable.html",
	}
}

type iamMFAAPI interface {
	awsapi.ListUsersAPI
	awsapi.GetLoginProfileAPI
	awsapi.ListMFADevicesAPI
}

func (c IAMUserNoMFA) Run(ctx context.Context, env *checks.Env) ([]checks.Finding, error) {
	return c.scan(ctx, env.Clients.IAM, env)
}

func (c IAMUserNoMFA) scan(ctx context.Context, api iamMFAAPI, env *checks.Env) ([]checks.Finding, error) {
	users, err := listIAMUsers(ctx, api)
	if err != nil {
		return nil, err
	}
	meta := c.Meta()
	var findings []checks.Finding
	for _, u := range users {
		name := aws.ToString(u.UserName)
		profile, err := api.GetLoginProfile(ctx, &iam.GetLoginProfileInput{UserName: u.UserName})
		if isAPIError(err, "NoSuchEntity") {
			continue // no console password
		}
		if err != nil {
			return nil, fmt.Errorf("get login profile for %s: %w", name, err)
		}
		mfa, err := api.ListMFADevices(ctx, &iam.ListMFADevicesInput{UserName: u.UserName})
		if err != nil {
			return nil, fmt.Errorf("list MFA devices for %s: %w", name, err)
		}
		if len(mfa.MFADevices) > 0 {
			continue
		}

		lastLogin := "never"
		if u.PasswordLastUsed != nil {
			lastLogin = fmt.Sprintf("%s (%d days ago)", u.PasswordLastUsed.Format("2006-01-02"), env.DaysSince(*u.PasswordLastUsed))
		}
		f := meta.NewFinding(env, aws.ToString(u.Arn))
		f.Title = fmt.Sprintf("IAM user %s has console access without MFA", name)
		f.Severity = checks.SeverityHigh
		f.Evidence = fmt.Sprintf("Console password set %s; last console sign-in %s; 0 MFA devices.",
			aws.ToTime(profile.LoginProfile.CreateDate).Format("2006-01-02"), lastLogin)
		f.Recommendation = "Have the user register an MFA device (IAM console > Users > Security credentials > Assign MFA device) and add a policy that denies actions without MFA. If the user never signs in to the console, remove the password instead."
		f.FixCommand = fmt.Sprintf("# If console access is not needed:\naws iam delete-login-profile --user-name %s", name)
		findings = append(findings, f)
	}
	return findings, nil
}
