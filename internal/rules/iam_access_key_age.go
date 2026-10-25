package rules

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
)

// IAMAccessKeyAge flags active access keys that are older than
// Config.AccessKeyMaxAgeDays or have not been used for that long.
type IAMAccessKeyAge struct{}

func (IAMAccessKeyAge) Meta() checks.Meta {
	return checks.Meta{
		ID:       "iam-access-key-age",
		Name:     "Old or unused IAM access keys",
		Category: checks.CategorySecurity,
		Global:   true,
		DocsURL:  "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#rotating_access_keys_console",
	}
}

type iamKeysAPI interface {
	awsapi.ListUsersAPI
	awsapi.ListAccessKeysAPI
	awsapi.GetAccessKeyLastUsedAPI
}

func (c IAMAccessKeyAge) Run(ctx context.Context, env *checks.Env) ([]checks.Finding, error) {
	return c.scan(ctx, env.Clients.IAM, env)
}

func (c IAMAccessKeyAge) scan(ctx context.Context, api iamKeysAPI, env *checks.Env) ([]checks.Finding, error) {
	users, err := listIAMUsers(ctx, api)
	if err != nil {
		return nil, err
	}
	maxAge := env.Config.AccessKeyMaxAgeDays
	meta := c.Meta()
	var findings []checks.Finding
	for _, u := range users {
		name := aws.ToString(u.UserName)
		pages := iam.NewListAccessKeysPaginator(api, &iam.ListAccessKeysInput{UserName: u.UserName})
		for pages.HasMorePages() {
			page, err := pages.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("list access keys for %s: %w", name, err)
			}
			for _, k := range page.AccessKeyMetadata {
				if k.Status != iamtypes.StatusTypeActive {
					continue
				}
				keyID := aws.ToString(k.AccessKeyId)
				used, err := api.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: k.AccessKeyId})
				if err != nil {
					return nil, fmt.Errorf("get access key last used for %s: %w", keyID, err)
				}
				age := env.DaysSince(aws.ToTime(k.CreateDate))

				var lastUsed *int
				lastUsedText := "never used"
				if used.AccessKeyLastUsed != nil && used.AccessKeyLastUsed.LastUsedDate != nil {
					d := env.DaysSince(*used.AccessKeyLastUsed.LastUsedDate)
					lastUsed = &d
					lastUsedText = fmt.Sprintf("last used %s (%d days ago) on %s", used.AccessKeyLastUsed.LastUsedDate.Format("2006-01-02"), d, aws.ToString(used.AccessKeyLastUsed.ServiceName))
				}
				unused := (lastUsed == nil && age >= maxAge) || (lastUsed != nil && *lastUsed >= maxAge)
				if age < maxAge && !unused {
					continue
				}

				f := meta.NewFinding(env, keyID)
				f.Severity = checks.SeverityMedium
				f.Evidence = fmt.Sprintf("Active key for user %s, created %s (%d days ago, limit %d), %s.", name, aws.ToTime(k.CreateDate).Format("2006-01-02"), age, maxAge, lastUsedText)
				if unused {
					f.Title = fmt.Sprintf("Access key %s for %s has not been used in %d+ days", keyID, name, maxAge)
					f.Recommendation = "Nothing depends on this key in practice. Deactivate it, wait a week for complaints, then delete it."
					f.FixCommand = fmt.Sprintf("aws iam update-access-key --user-name %s --access-key-id %s --status Inactive", name, keyID)
				} else {
					f.Title = fmt.Sprintf("Access key %s for %s is %d days old", keyID, name, age)
					f.Recommendation = "Rotate the key: create a second key, move every consumer to it, deactivate the old one, then delete it. Better still, replace long-lived keys with IAM roles or IAM Identity Center."
					f.FixCommand = fmt.Sprintf("aws iam create-access-key --user-name %[1]s\n# update every consumer to the new key, then:\naws iam update-access-key --user-name %[1]s --access-key-id %[2]s --status Inactive", name, keyID)
				}
				findings = append(findings, f)
			}
		}
	}
	return findings, nil
}
