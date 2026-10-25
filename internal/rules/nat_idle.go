package rules

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
	"github.com/minhhieu21193/cloudaudit/internal/pricing"
)

// natIdleBytes is the traffic below which a NAT gateway counts as idle over
// the lookback window.
const natIdleBytes = 1 << 30 // 1 GiB

// NATIdle flags NAT gateways that sent almost no traffic over the lookback
// window. They bill hourly regardless of traffic.
type NATIdle struct{}

func (NATIdle) Meta() checks.Meta {
	return checks.Meta{
		ID:       "nat-idle",
		Name:     "Idle NAT Gateways",
		Category: checks.CategoryCost,
		DocsURL:  "https://docs.aws.amazon.com/vpc/latest/userguide/nat-gateway-cloudwatch.html",
	}
}

func (c NATIdle) Run(ctx context.Context, env *checks.Env) ([]checks.Finding, error) {
	return c.scan(ctx, env.Clients.EC2, env.Clients.CloudWatch, env)
}

func (c NATIdle) scan(ctx context.Context, api awsapi.DescribeNatGatewaysAPI, cw awsapi.GetMetricStatisticsAPI, env *checks.Env) ([]checks.Finding, error) {
	prices, exact := pricing.For(env.Region)
	cost := pricing.Monthly(prices.NATGatewayHour)
	lookback := env.Config.IdleLookbackDays
	meta := c.Meta()
	var findings []checks.Finding

	pages := ec2.NewDescribeNatGatewaysPaginator(api, &ec2.DescribeNatGatewaysInput{
		Filter: []ec2types.Filter{{Name: aws.String("state"), Values: []string{"available"}}},
	})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe NAT gateways: %w", err)
		}
		for _, n := range page.NatGateways {
			id := aws.ToString(n.NatGatewayId)
			// Too young to judge: the window would include days before it existed.
			if env.DaysSince(aws.ToTime(n.CreateTime)) < lookback {
				continue
			}
			sent, err := metricSum(ctx, cw, env, "AWS/NATGateway", "BytesOutToDestination", "NatGatewayId", id)
			if err != nil {
				return nil, err
			}
			if sent >= natIdleBytes {
				continue
			}
			f := meta.NewFinding(env, id)
			f.Title = fmt.Sprintf("NAT Gateway %s sent %s in %d days", displayName(id, ec2Name(n.Tags)), humanBytes(sent), lookback)
			f.Severity = costSeverity(cost)
			f.EstMonthlyUSD = cost
			f.Evidence = fmt.Sprintf("BytesOutToDestination over the last %d days: %s (idle threshold %s). VPC %s, subnet %s. Billed $%.3f/hour plus data processing.%s",
				lookback, humanBytes(sent), humanBytes(natIdleBytes), aws.ToString(n.VpcId), aws.ToString(n.SubnetId), prices.NATGatewayHour, priceNote(exact))
			f.Recommendation = "Check the route tables that point at this gateway. If nothing needs outbound internet from those subnets, delete it and release its Elastic IP; VPC endpoints may cover AWS-service traffic more cheaply."
			f.FixCommand = fmt.Sprintf("aws ec2 describe-route-tables --region %[1]s --filters Name=route.nat-gateway-id,Values=%[2]s\naws ec2 delete-nat-gateway --region %[1]s --nat-gateway-id %[2]s", env.Region, id)
			for _, addr := range n.NatGatewayAddresses {
				if addr.AllocationId != nil {
					f.FixCommand += fmt.Sprintf("\naws ec2 release-address --region %s --allocation-id %s  # after the gateway is deleted", env.Region, *addr.AllocationId)
				}
			}
			findings = append(findings, f)
		}
	}
	return findings, nil
}
