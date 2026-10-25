package rules

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
)

// listDBInstances returns every RDS instance in the region. Shared by the
// rds-unencrypted and rds-public checks.
func listDBInstances(ctx context.Context, api awsapi.DescribeDBInstancesAPI) ([]rdstypes.DBInstance, error) {
	var out []rdstypes.DBInstance
	pages := rds.NewDescribeDBInstancesPaginator(api, &rds.DescribeDBInstancesInput{})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe DB instances: %w", err)
		}
		out = append(out, page.DBInstances...)
	}
	return out, nil
}

func dbLabel(db rdstypes.DBInstance) string {
	return fmt.Sprintf("%s (%s %s)", aws.ToString(db.DBInstanceIdentifier), aws.ToString(db.Engine), aws.ToString(db.DBInstanceClass))
}
