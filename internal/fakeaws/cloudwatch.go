package fakeaws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
)

var _ awsapi.CloudWatch = (*CloudWatch)(nil)

// MetricKey identifies a metric series by its single dimension value (for
// example a NAT gateway ID or an "app/name/id" load balancer suffix).
type MetricKey struct {
	Namespace string
	Metric    string
	Dimension string
}

type CloudWatch struct {
	// Sums maps a series to its daily Sum datapoints. Missing series
	// return no datapoints, as CloudWatch does for an idle resource.
	Sums map[MetricKey][]float64
	Err  error
}

func (f *CloudWatch) GetMetricStatistics(_ context.Context, in *cloudwatch.GetMetricStatisticsInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	key := MetricKey{Namespace: aws.ToString(in.Namespace), Metric: aws.ToString(in.MetricName)}
	if len(in.Dimensions) > 0 {
		key.Dimension = aws.ToString(in.Dimensions[0].Value)
	}
	out := &cloudwatch.GetMetricStatisticsOutput{Label: in.MetricName}
	for i, v := range f.Sums[key] {
		ts := aws.ToTime(in.StartTime).Add(timeStep(in.Period, i))
		out.Datapoints = append(out.Datapoints, cwtypes.Datapoint{Sum: aws.Float64(v), Timestamp: aws.Time(ts)})
	}
	return out, nil
}

func timeStep(periodSeconds *int32, i int) time.Duration {
	return time.Duration(aws.ToInt32(periodSeconds)) * time.Second * time.Duration(i)
}
