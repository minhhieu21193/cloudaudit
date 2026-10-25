package rules

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
)

// adminPorts are the remote-admin and database ports that must never be
// open to the internet. Database ports rank CRITICAL: an exposed database is
// usually one weak password away from a breach.
var adminPorts = []struct {
	port     int32
	service  string
	severity checks.Severity
}{
	{22, "SSH", checks.SeverityHigh},
	{3389, "RDP", checks.SeverityHigh},
	{3306, "MySQL", checks.SeverityCritical},
	{5432, "PostgreSQL", checks.SeverityCritical},
	{6379, "Redis", checks.SeverityCritical},
	{27017, "MongoDB", checks.SeverityCritical},
}

const (
	anyIPv4 = "0.0.0.0/0"
	anyIPv6 = "::/0"
)

// SGOpenAdminPorts flags security groups that allow the whole internet in on
// an admin or database port, including "all traffic" rules.
type SGOpenAdminPorts struct{}

func (SGOpenAdminPorts) Meta() checks.Meta {
	return checks.Meta{
		ID:       "sg-open-admin-ports",
		Name:     "Security groups open to the internet on admin/DB ports",
		Category: checks.CategorySecurity,
		DocsURL:  "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html",
	}
}

func (c SGOpenAdminPorts) Run(ctx context.Context, env *checks.Env) ([]checks.Finding, error) {
	return c.scan(ctx, env.Clients.EC2, env)
}

func (c SGOpenAdminPorts) scan(ctx context.Context, api awsapi.DescribeSecurityGroupsAPI, env *checks.Env) ([]checks.Finding, error) {
	meta := c.Meta()
	var findings []checks.Finding
	pages := ec2.NewDescribeSecurityGroupsPaginator(api, &ec2.DescribeSecurityGroupsInput{})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe security groups: %w", err)
		}
		for _, sg := range page.SecurityGroups {
			if f, ok := c.evaluate(meta, env, sg); ok {
				findings = append(findings, f)
			}
		}
	}
	return findings, nil
}

func (SGOpenAdminPorts) evaluate(meta checks.Meta, env *checks.Env, sg ec2types.SecurityGroup) (checks.Finding, bool) {
	id := aws.ToString(sg.GroupId)
	var exposed []string
	var fixes []string
	severity := checks.Severity(0)

	for _, perm := range sg.IpPermissions {
		var sources []string
		for _, r := range perm.IpRanges {
			if aws.ToString(r.CidrIp) == anyIPv4 {
				sources = append(sources, anyIPv4)
			}
		}
		for _, r := range perm.Ipv6Ranges {
			if aws.ToString(r.CidrIpv6) == anyIPv6 {
				sources = append(sources, anyIPv6)
			}
		}
		if len(sources) == 0 {
			continue
		}

		proto := aws.ToString(perm.IpProtocol)
		allTraffic := proto == "-1"
		if !allTraffic && proto != "tcp" && proto != "6" {
			continue
		}
		var hits []string
		for _, ap := range adminPorts {
			if allTraffic || (aws.ToInt32(perm.FromPort) <= ap.port && ap.port <= aws.ToInt32(perm.ToPort)) {
				hits = append(hits, fmt.Sprintf("%d/%s", ap.port, ap.service))
				severity = max(severity, ap.severity)
			}
		}
		if len(hits) == 0 {
			continue
		}
		rule := fmt.Sprintf("tcp %d-%d", aws.ToInt32(perm.FromPort), aws.ToInt32(perm.ToPort))
		if aws.ToInt32(perm.FromPort) == aws.ToInt32(perm.ToPort) {
			rule = fmt.Sprintf("tcp %d", aws.ToInt32(perm.FromPort))
		}
		if allTraffic {
			rule = "all traffic"
			severity = checks.SeverityCritical
		}
		exposed = append(exposed, fmt.Sprintf("%s from %s (%s)", rule, strings.Join(sources, ", "), strings.Join(hits, ", ")))
		for _, src := range sources {
			fixes = append(fixes, revokeCommand(env.Region, id, perm, src))
		}
	}
	if len(exposed) == 0 {
		return checks.Finding{}, false
	}
	sort.Strings(exposed)

	f := meta.NewFinding(env, id)
	f.Title = fmt.Sprintf("Security group %s is open to the internet on admin/DB ports", displayName(id, aws.ToString(sg.GroupName)))
	f.Severity = severity
	f.Evidence = fmt.Sprintf("VPC %s. Inbound rules: %s.", aws.ToString(sg.VpcId), strings.Join(exposed, "; "))
	f.Recommendation = "Remove the 0.0.0.0/0 and ::/0 rules. Reach instances through SSM Session Manager or a VPN, and allow databases only from application security groups."
	f.FixCommand = strings.Join(fixes, "\n")
	return f, true
}

func revokeCommand(region, groupID string, perm ec2types.IpPermission, source string) string {
	proto := aws.ToString(perm.IpProtocol)
	ranges := fmt.Sprintf("IpRanges=[{CidrIp=%s}]", source)
	if source == anyIPv6 {
		ranges = fmt.Sprintf("Ipv6Ranges=[{CidrIpv6=%s}]", source)
	}
	ports := fmt.Sprintf(",FromPort=%d,ToPort=%d", aws.ToInt32(perm.FromPort), aws.ToInt32(perm.ToPort))
	if proto == "-1" {
		ports = ""
	}
	return fmt.Sprintf("aws ec2 revoke-security-group-ingress --region %s --group-id %s --ip-permissions 'IpProtocol=%s%s,%s'", region, groupID, proto, ports, ranges)
}
