package fakeaws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
)

var _ awsapi.RDS = (*RDS)(nil)

type RDS struct {
	DBInstances []rdstypes.DBInstance
	Err         error
}

func (f *RDS) DescribeDBInstances(context.Context, *rds.DescribeDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return &rds.DescribeDBInstancesOutput{DBInstances: f.DBInstances}, nil
}
