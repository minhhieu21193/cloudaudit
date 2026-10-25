package rules

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/minhhieu21193/cloudaudit/internal/fakeaws"
)

const arnPrefix = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:"

func lb(name string, kind elbtypes.LoadBalancerTypeEnum, ageDays int) elbtypes.LoadBalancer {
	short := map[elbtypes.LoadBalancerTypeEnum]string{elbtypes.LoadBalancerTypeEnumApplication: "app", elbtypes.LoadBalancerTypeEnumNetwork: "net", elbtypes.LoadBalancerTypeEnumGateway: "gwy"}[kind]
	return elbtypes.LoadBalancer{
		LoadBalancerArn:  aws.String(arnPrefix + "loadbalancer/" + short + "/" + name + "/0123456789abcdef"),
		LoadBalancerName: aws.String(name),
		Type:             kind,
		CreatedTime:      aws.Time(daysAgo(ageDays)),
		DNSName:          aws.String(name + ".example.elb.amazonaws.com"),
	}
}

func tg(name string, lbs ...elbtypes.LoadBalancer) elbtypes.TargetGroup {
	g := elbtypes.TargetGroup{TargetGroupArn: aws.String(arnPrefix + "targetgroup/" + name + "/1")}
	for _, l := range lbs {
		g.LoadBalancerArns = append(g.LoadBalancerArns, *l.LoadBalancerArn)
	}
	return g
}

func health(states ...elbtypes.TargetHealthStateEnum) []elbtypes.TargetHealthDescription {
	var out []elbtypes.TargetHealthDescription
	for _, s := range states {
		out = append(out, elbtypes.TargetHealthDescription{TargetHealth: &elbtypes.TargetHealth{State: s}})
	}
	return out
}

func TestELBIdle(t *testing.T) {
	noTargets := lb("no-targets", elbtypes.LoadBalancerTypeEnumApplication, 100)
	unhealthy := lb("unhealthy", elbtypes.LoadBalancerTypeEnumApplication, 100)
	quiet := lb("quiet-nlb", elbtypes.LoadBalancerTypeEnumNetwork, 100)
	busy := lb("busy", elbtypes.LoadBalancerTypeEnumApplication, 100)
	young := lb("young", elbtypes.LoadBalancerTypeEnumApplication, 2)
	gateway := lb("gwlb", elbtypes.LoadBalancerTypeEnumGateway, 100)

	tgUnhealthy, tgQuiet, tgBusy := tg("unhealthy", unhealthy), tg("quiet", quiet), tg("busy", busy)
	elb := &fakeaws.ELBv2{
		LoadBalancers: []elbtypes.LoadBalancer{noTargets, unhealthy, quiet, busy, young, gateway},
		TargetGroups:  []elbtypes.TargetGroup{tgUnhealthy, tgQuiet, tgBusy},
		TargetHealth: map[string][]elbtypes.TargetHealthDescription{
			*tgUnhealthy.TargetGroupArn: health(elbtypes.TargetHealthStateEnumUnhealthy, elbtypes.TargetHealthStateEnumDraining),
			*tgQuiet.TargetGroupArn:     health(elbtypes.TargetHealthStateEnumHealthy),
			*tgBusy.TargetGroupArn:      health(elbtypes.TargetHealthStateEnumHealthy),
		},
	}
	cw := &fakeaws.CloudWatch{Sums: map[fakeaws.MetricKey][]float64{
		{Namespace: "AWS/NetworkELB", Metric: "NewFlowCount", Dimension: "net/quiet-nlb/0123456789abcdef"}: {3, 4},
		{Namespace: "AWS/ApplicationELB", Metric: "RequestCount", Dimension: "app/busy/0123456789abcdef"}:  {50000},
	}}

	got, err := ELBIdle{}.scan(context.Background(), elb, cw, testEnv("eu-west-1"))
	if err != nil {
		t.Fatal(err)
	}
	m := byResource(t, got)
	if len(m) != 3 {
		t.Fatalf("got %d findings %v, want no-targets, unhealthy, quiet-nlb", len(m), m)
	}
	if f := m[*noTargets.LoadBalancerArn]; !strings.Contains(f.Evidence, "across 0 target group") {
		t.Errorf("no-targets evidence = %q", f.Evidence)
	}
	if f := m[*unhealthy.LoadBalancerArn]; !strings.Contains(f.Evidence, "No healthy targets across 1") {
		t.Errorf("unhealthy evidence = %q", f.Evidence)
	}
	q := m[*quiet.LoadBalancerArn]
	if !strings.Contains(q.Evidence, "NewFlowCount over the last 14 days: 7") || !strings.HasPrefix(q.Title, "Network") {
		t.Errorf("quiet-nlb = %+v", q)
	}
	approxUSD(t, q.EstMonthlyUSD, 0.0252*730)
}

func TestLBDimension(t *testing.T) {
	if got := lbDimension(arnPrefix + "loadbalancer/app/web/50dc6c495c0c9188"); got != "app/web/50dc6c495c0c9188" {
		t.Errorf("lbDimension = %q", got)
	}
}
