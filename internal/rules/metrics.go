package rules

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
)

const secondsPerDay = 24 * 60 * 60

// metricSum totals a CloudWatch metric over the last Config.IdleLookbackDays
// using daily Sum datapoints.
func metricSum(ctx context.Context, api awsapi.GetMetricStatisticsAPI, env *checks.Env, namespace, metric, dimName, dimValue string) (float64, error) {
	days := env.Config.IdleLookbackDays
	out, err := api.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String(namespace),
		MetricName: aws.String(metric),
		Dimensions: []cwtypes.Dimension{{Name: aws.String(dimName), Value: aws.String(dimValue)}},
		StartTime:  aws.Time(env.Now.Add(-time.Duration(days) * 24 * time.Hour)),
		EndTime:    aws.Time(env.Now),
		Period:     aws.Int32(secondsPerDay),
		Statistics: []cwtypes.Statistic{cwtypes.StatisticSum},
	})
	if err != nil {
		return 0, fmt.Errorf("get %s %s for %s: %w", namespace, metric, dimValue, err)
	}
	var sum float64
	for _, dp := range out.Datapoints {
		sum += aws.ToFloat64(dp.Sum)
	}
	return sum, nil
}

func humanBytes(b float64) string {
	const unit = 1024.0
	switch {
	case b >= unit*unit*unit:
		return fmt.Sprintf("%.2f GiB", b/(unit*unit*unit))
	case b >= unit*unit:
		return fmt.Sprintf("%.1f MiB", b/(unit*unit))
	case b >= unit:
		return fmt.Sprintf("%.1f KiB", b/unit)
	default:
		return fmt.Sprintf("%.0f B", b)
	}
}
