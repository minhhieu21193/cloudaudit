package rules

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
	"github.com/minhhieu21193/cloudaudit/internal/pricing"
)

// elbIdleRequests is the request (ALB) or new-flow (NLB) count below which a
// load balancer counts as idle over the lookback window.
const elbIdleRequests = 100

// ELBIdle flags Application and Network Load Balancers that have no healthy
// targets, or that served almost no traffic over the lookback window.
type ELBIdle struct{}

func (ELBIdle) Meta() checks.Meta {
	return checks.Meta{
		ID:       "elb-idle",
		Name:     "Idle load balancers",
		Category: checks.CategoryCost,
		DocsURL:  "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-cloudwatch-metrics.html",
	}
}

func (c ELBIdle) Run(ctx context.Context, env *checks.Env) ([]checks.Finding, error) {
	return c.scan(ctx, env.Clients.ELBv2, env.Clients.CloudWatch, env)
}

func (c ELBIdle) scan(ctx context.Context, api awsapi.ELBv2, cw awsapi.GetMetricStatisticsAPI, env *checks.Env) ([]checks.Finding, error) {
	prices, exact := pricing.For(env.Region)
	lookback := env.Config.IdleLookbackDays
	meta := c.Meta()
	var findings []checks.Finding

	pages := elbv2.NewDescribeLoadBalancersPaginator(api, &elbv2.DescribeLoadBalancersInput{})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe load balancers: %w", err)
		}
		for _, lb := range page.LoadBalancers {
			var hourly float64
			var namespace, metric string
			switch lb.Type {
			case elbtypes.LoadBalancerTypeEnumApplication:
				hourly, namespace, metric = prices.ApplicationLBHour, "AWS/ApplicationELB", "RequestCount"
			case elbtypes.LoadBalancerTypeEnumNetwork:
				hourly, namespace, metric = prices.NetworkLBHour, "AWS/NetworkELB", "NewFlowCount"
			default:
				continue // gateway load balancers are priced and used differently
			}
			if env.DaysSince(aws.ToTime(lb.CreatedTime)) < lookback {
				continue
			}
			arn := aws.ToString(lb.LoadBalancerArn)
			name := aws.ToString(lb.LoadBalancerName)

			healthy, groups, err := healthyTargets(ctx, api, arn)
			if err != nil {
				return nil, err
			}
			var reason string
			if healthy == 0 {
				reason = fmt.Sprintf("No healthy targets across %d target group(s).", groups)
			} else {
				traffic, err := metricSum(ctx, cw, env, namespace, metric, "LoadBalancer", lbDimension(arn))
				if err != nil {
					return nil, err
				}
				if traffic >= elbIdleRequests {
					continue
				}
				reason = fmt.Sprintf("%s over the last %d days: %.0f (idle threshold %d). %d healthy target(s).", metric, lookback, traffic, elbIdleRequests, healthy)
			}

			cost := pricing.Monthly(hourly)
			f := meta.NewFinding(env, arn)
			f.Title = fmt.Sprintf("%s load balancer %s looks idle", lbKind(lb.Type), name)
			f.Severity = costSeverity(cost)
			f.EstMonthlyUSD = cost
			f.Evidence = fmt.Sprintf("%s Scheme %s. Base price $%.4f/hour; capacity units (LCU) not included.%s", reason, lb.Scheme, hourly, priceNote(exact))
			f.Recommendation = "Confirm no DNS record or client still points at it (check Route 53 and the DNS name " + aws.ToString(lb.DNSName) + "), then delete it. Turn off deletion protection first if it is on."
			f.FixCommand = fmt.Sprintf("aws elbv2 delete-load-balancer --region %s --load-balancer-arn %s", env.Region, arn)
			findings = append(findings, f)
		}
	}
	return findings, nil
}

func healthyTargets(ctx context.Context, api awsapi.ELBv2, lbARN string) (healthy, groups int, err error) {
	pages := elbv2.NewDescribeTargetGroupsPaginator(api, &elbv2.DescribeTargetGroupsInput{LoadBalancerArn: aws.String(lbARN)})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return 0, 0, fmt.Errorf("describe target groups for %s: %w", lbARN, err)
		}
		for _, tg := range page.TargetGroups {
			groups++
			out, err := api.DescribeTargetHealth(ctx, &elbv2.DescribeTargetHealthInput{TargetGroupArn: tg.TargetGroupArn})
			if err != nil {
				return 0, 0, fmt.Errorf("describe target health for %s: %w", aws.ToString(tg.TargetGroupArn), err)
			}
			for _, d := range out.TargetHealthDescriptions {
				if d.TargetHealth != nil && d.TargetHealth.State == elbtypes.TargetHealthStateEnumHealthy {
					healthy++
				}
			}
		}
	}
	return healthy, groups, nil
}

// lbDimension turns a load balancer ARN into the CloudWatch LoadBalancer
// dimension value, e.g. "app/my-alb/50dc6c495c0c9188".
func lbDimension(arn string) string {
	_, after, found := strings.Cut(arn, ":loadbalancer/")
	if !found {
		return arn
	}
	return after
}

func lbKind(t elbtypes.LoadBalancerTypeEnum) string {
	if t == elbtypes.LoadBalancerTypeEnumNetwork {
		return "Network"
	}
	return "Application"
}
