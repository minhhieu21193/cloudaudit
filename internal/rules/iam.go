package rules

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
)

// listIAMUsers returns every IAM user. The IAM checks deliberately use
// per-user List/Get calls instead of GenerateCredentialReport, which would
// create a report object in the account.
func listIAMUsers(ctx context.Context, api awsapi.ListUsersAPI) ([]iamtypes.User, error) {
	var users []iamtypes.User
	pages := iam.NewListUsersPaginator(api, &iam.ListUsersInput{})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list users: %w", err)
		}
		users = append(users, page.Users...)
	}
	return users, nil
}

// isAPIError reports whether err is an AWS API error with the given code.
func isAPIError(err error, code string) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == code
}
