package rules

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
	"github.com/minhhieu21193/cloudaudit/internal/fakeaws"
)

func tcp(from, to int32, cidrs ...string) ec2types.IpPermission {
	p := ec2types.IpPermission{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(from), ToPort: aws.Int32(to)}
	for _, c := range cidrs {
		if strings.Contains(c, ":") {
			p.Ipv6Ranges = append(p.Ipv6Ranges, ec2types.Ipv6Range{CidrIpv6: aws.String(c)})
		} else {
			p.IpRanges = append(p.IpRanges, ec2types.IpRange{CidrIp: aws.String(c)})
		}
	}
	return p
}

func sg(id string, perms ...ec2types.IpPermission) ec2types.SecurityGroup {
	return ec2types.SecurityGroup{GroupId: aws.String(id), GroupName: aws.String(id + "-name"), VpcId: aws.String("vpc-1"), IpPermissions: perms}
}

func TestSGOpenAdminPorts(t *testing.T) {
	fake := &fakeaws.EC2{SecurityGroups: []ec2types.SecurityGroup{
		sg("sg-ssh", tcp(22, 22, "0.0.0.0/0")),
		sg("sg-db-v6", tcp(5432, 5432, "::/0")),
		sg("sg-range", tcp(3000, 4000, "0.0.0.0/0", "::/0")), // covers 3306 and 3389
		sg("sg-all", ec2types.IpPermission{IpProtocol: aws.String("-1"), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}}),
		sg("sg-https", tcp(443, 443, "0.0.0.0/0")),
		sg("sg-private", tcp(22, 22, "10.0.0.0/8")),
		sg("sg-udp", ec2types.IpPermission{IpProtocol: aws.String("udp"), FromPort: aws.Int32(0), ToPort: aws.Int32(65535), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}}),
	}}
	got, err := SGOpenAdminPorts{}.scan(context.Background(), fake, testEnv("ap-northeast-1"))
	if err != nil {
		t.Fatal(err)
	}
	m := byResource(t, got)
	want := map[string]checks.Severity{
		"sg-ssh":   checks.SeverityHigh,
		"sg-db-v6": checks.SeverityCritical,
		"sg-range": checks.SeverityCritical,
		"sg-all":   checks.SeverityCritical,
	}
	if len(m) != len(want) {
		t.Fatalf("got %d findings %v, want %v", len(m), m, want)
	}
	for id, sev := range want {
		if m[id].Severity != sev {
			t.Errorf("%s severity = %v, want %v", id, m[id].Severity, sev)
		}
		if m[id].EstMonthlyUSD != 0 || m[id].Category != checks.CategorySecurity {
			t.Errorf("%s should be a security finding with no cost: %+v", id, m[id])
		}
	}
	r := m["sg-range"]
	if !strings.Contains(r.Evidence, "3306/MySQL") || !strings.Contains(r.Evidence, "3389/RDP") {
		t.Errorf("range evidence = %q", r.Evidence)
	}
	if strings.Count(r.FixCommand, "revoke-security-group-ingress") != 2 || !strings.Contains(r.FixCommand, "Ipv6Ranges=[{CidrIpv6=::/0}]") {
		t.Errorf("range fix = %q", r.FixCommand)
	}
	if !strings.Contains(m["sg-ssh"].FixCommand, "'IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=0.0.0.0/0}]'") {
		t.Errorf("ssh fix = %q", m["sg-ssh"].FixCommand)
	}
	if !strings.Contains(m["sg-all"].FixCommand, "'IpProtocol=-1,IpRanges=") {
		t.Errorf("all-traffic fix = %q", m["sg-all"].FixCommand)
	}
}
