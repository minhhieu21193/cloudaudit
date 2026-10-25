package rules

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
)

// RDSUnencrypted flags RDS instances without storage encryption.
type RDSUnencrypted struct{}

func (RDSUnencrypted) Meta() checks.Meta {
	return checks.Meta{
		ID:       "rds-unencrypted",
		Name:     "Unencrypted RDS instances",
		Category: checks.CategorySecurity,
		DocsURL:  "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
	}
}

func (c RDSUnencrypted) Run(ctx context.Context, env *checks.Env) ([]checks.Finding, error) {
	return c.scan(ctx, env.Clients.RDS, env)
}

func (c RDSUnencrypted) scan(ctx context.Context, api awsapi.DescribeDBInstancesAPI, env *checks.Env) ([]checks.Finding, error) {
	dbs, err := listDBInstances(ctx, api)
	if err != nil {
		return nil, err
	}
	meta := c.Meta()
	var findings []checks.Finding
	for _, db := range dbs {
		if aws.ToBool(db.StorageEncrypted) {
			continue
		}
		id := aws.ToString(db.DBInstanceIdentifier)
		f := meta.NewFinding(env, id)
		f.Title = fmt.Sprintf("RDS instance %s is not encrypted at rest", dbLabel(db))
		f.Severity = checks.SeverityHigh
		f.Evidence = fmt.Sprintf("StorageEncrypted=false, %d GiB allocated. Its automated backups and snapshots are unencrypted too.", aws.ToInt32(db.AllocatedStorage))
		f.Recommendation = "Encryption cannot be turned on in place. Snapshot the instance, copy the snapshot with a KMS key, restore from the encrypted copy and cut over during a maintenance window."
		if cluster := aws.ToString(db.DBClusterIdentifier); cluster != "" {
			f.Evidence += fmt.Sprintf(" Member of Aurora cluster %s.", cluster)
			f.Recommendation = "Aurora encryption is set per cluster and cannot be changed in place. Snapshot the cluster, copy the snapshot with a KMS key, restore a new encrypted cluster and cut over."
			f.FixCommand = fmt.Sprintf("aws rds create-db-cluster-snapshot --region %[1]s --db-cluster-identifier %[2]s --db-cluster-snapshot-identifier %[2]s-pre-encrypt\naws rds copy-db-cluster-snapshot --region %[1]s --source-db-cluster-snapshot-identifier %[2]s-pre-encrypt --target-db-cluster-snapshot-identifier %[2]s-encrypted --kms-key-id alias/aws/rds", env.Region, cluster)
		} else {
			f.FixCommand = fmt.Sprintf("aws rds create-db-snapshot --region %[1]s --db-instance-identifier %[2]s --db-snapshot-identifier %[2]s-pre-encrypt\naws rds copy-db-snapshot --region %[1]s --source-db-snapshot-identifier %[2]s-pre-encrypt --target-db-snapshot-identifier %[2]s-encrypted --kms-key-id alias/aws/rds\naws rds restore-db-instance-from-db-snapshot --region %[1]s --db-instance-identifier %[2]s-encrypted --db-snapshot-identifier %[2]s-encrypted", env.Region, id)
		}
		findings = append(findings, f)
	}
	return findings, nil
}
