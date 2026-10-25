package rules

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
	"github.com/minhhieu21193/cloudaudit/internal/pricing"
)

// EIPUnassociated flags Elastic IPs that are allocated but not associated
// with anything. Every public IPv4 address is billed hourly.
type EIPUnassociated struct{}

func (EIPUnassociated) Meta() checks.Meta {
	return checks.Meta{
		ID:       "eip-unassociated",
		Name:     "Unassociated Elastic IPs",
		Category: checks.CategoryCost,
		DocsURL:  "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/working-with-eips.html#using-instance-addressing-eips-releasing",
	}
}

func (c EIPUnassociated) Run(ctx context.Context, env *checks.Env) ([]checks.Finding, error) {
	return c.scan(ctx, env.Clients.EC2, env)
}

func (c EIPUnassociated) scan(ctx context.Context, api awsapi.DescribeAddressesAPI, env *checks.Env) ([]checks.Finding, error) {
	out, err := api.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return nil, fmt.Errorf("describe addresses: %w", err)
	}
	prices, exact := pricing.For(env.Region)
	cost := pricing.Monthly(prices.PublicIPv4Hour)
	meta := c.Meta()

	var findings []checks.Finding
	for _, a := range out.Addresses {
		// Service-managed addresses (for example, owned by a load balancer)
		// cannot be released by the account owner.
		if a.AssociationId != nil || a.NetworkInterfaceId != nil || a.ServiceManaged != "" {
			continue
		}
		id := aws.ToString(a.AllocationId)
		ip := aws.ToString(a.PublicIp)
		f := meta.NewFinding(env, id)
		f.Title = fmt.Sprintf("Elastic IP %s is not associated", withName(ip, ec2Name(a.Tags)))
		f.Severity = costSeverity(cost)
		f.EstMonthlyUSD = cost
		f.Evidence = fmt.Sprintf("Allocation %s has no association and no network interface. Public IPv4 is billed at $%.3f/hour whether used or idle.%s",
			id, prices.PublicIPv4Hour, priceNote(exact))
		f.Recommendation = "Release the address unless it is allow-listed somewhere and must be kept; if so, document why."
		f.FixCommand = fmt.Sprintf("aws ec2 release-address --region %s --allocation-id %s", env.Region, id)
		findings = append(findings, f)
	}
	return findings, nil
}
