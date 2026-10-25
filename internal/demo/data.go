package demo

import (
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
	"github.com/minhhieu21193/cloudaudit/internal/fakeaws"
)

// tokyo is the production region: a few years of drift, some leftovers from
// a database migration and a retired reporting stack.
func (b *Backend) tokyo() awsapi.Clients {
	const vpc = "vpc-0a7c9e1b3d5f70246"
	const r = tokyo
	webALB := lbARN(r, "app", "prod-web", "5f3a8c1e9b7d2046")
	stagingALB := lbARN(r, "app", "staging-web", "8e2b6d4f1a3c5079")
	mqttNLB := lbARN(r, "net", "legacy-mqtt", "3c7e1a9f5b2d8064")
	tgWeb, tgStaging, tgMQTT := targetGroup(r, "prod-web", webALB), targetGroup(r, "staging-web", stagingALB), targetGroup(r, "legacy-mqtt", mqttNLB)

	ec2 := &fakeaws.EC2{
		EBSEncryptionByDefault: true,
		Volumes: []ec2types.Volume{
			// Unattached leftovers.
			b.volume("vol-0a1f3c5e7b9d24680", "jenkins-data-old", 500, ec2types.VolumeTypeGp2, 412, ""),
			b.volume("vol-0b2e4d6f8a1c35791", "db-migration-scratch", 100, ec2types.VolumeTypeGp3, 63, ""),
			// Running fleet: two gp2 volumes worth converting, gp3 roots.
			b.volume("vol-0c3d5e7f9a1b46802", "prod-db-data", 1500, ec2types.VolumeTypeGp2, 690, "i-0a12b34c56d78e901"),
			b.volume("vol-0d4e6f8a1b2c57913", "api-1-data", 200, ec2types.VolumeTypeGp2, 540, "i-0b23c45d67e89f012"),
			b.volume("vol-0e5f7a9b2c3d68024", "prod-db-root", 30, ec2types.VolumeTypeGp3, 690, "i-0a12b34c56d78e901"),
			b.volume("vol-0f6a8b1c3d4e79135", "api-1-root", 30, ec2types.VolumeTypeGp3, 540, "i-0b23c45d67e89f012"),
			// Volumes of the retired reporting worker (counted by ec2-stopped only).
			b.volume("vol-01a2b3c4d5e6f7081", "reporting-worker-root", 100, ec2types.VolumeTypeGp2, 820, "i-0c34d56e78f90a123"),
			b.volume("vol-02b3c4d5e6f7a8192", "reporting-worker-data", 1000, ec2types.VolumeTypeGp2, 820, "i-0c34d56e78f90a123"),
		},
		Instances: []ec2types.Instance{
			b.instance("i-0a12b34c56d78e901", "prod-db", ec2types.InstanceTypeR6gXlarge, ec2types.InstanceStateNameRunning, 0, "vol-0e5f7a9b2c3d68024", "vol-0c3d5e7f9a1b46802"),
			b.instance("i-0b23c45d67e89f012", "api-1", ec2types.InstanceTypeM6gLarge, ec2types.InstanceStateNameRunning, 0, "vol-0f6a8b1c3d4e79135", "vol-0d4e6f8a1b2c57913"),
			b.instance("i-0c34d56e78f90a123", "reporting-worker", ec2types.InstanceTypeM5Xlarge, ec2types.InstanceStateNameStopped, 147, "vol-01a2b3c4d5e6f7081", "vol-02b3c4d5e6f7a8192"),
			b.instance("i-0d45e67f89a01b234", "load-test-runner", ec2types.InstanceTypeC5Large, ec2types.InstanceStateNameStopped, 6),
		},
		Snapshots: []ec2types.Snapshot{
			b.snapshot("snap-0a9b8c7d6e5f40312", "vol-0123456789abcdef0", "pre-migration backup of mysql-legacy", 800, 401),
			b.snapshot("snap-0b8c7d6e5f4a30423", "vol-0234567890abcdef1", "weekly-backup jenkins", 500, 380),
			b.snapshot("snap-0c7d6e5f4a3b20534", "vol-0234567890abcdef1", "weekly-backup jenkins", 500, 373),
			b.snapshot("snap-0d6e5f4a3b2c10645", "vol-0345678901abcdef2", "", 200, 215),
			// Not findings: backs an AMI, source still exists, too recent.
			b.snapshot("snap-0e5f4a3b2c1d00756", "vol-0456789012abcdef3", "Created by CreateImage(i-0b23c45d67e89f012) for ami-0f1e2d3c4b5a69780", 30, 300),
			b.snapshot("snap-0f4a3b2c1d0e90867", "vol-0c3d5e7f9a1b46802", "prod-db nightly", 1500, 120),
			b.snapshot("snap-01b2c3d4e5f6a7978", "vol-0567890123abcdef4", "ad-hoc before resize", 100, 12),
		},
		Images: []ec2types.Image{{
			ImageId: aws.String("ami-0f1e2d3c4b5a69780"), Name: aws.String("api-golden-2025-12"),
			BlockDeviceMappings: []ec2types.BlockDeviceMapping{{Ebs: &ec2types.EbsBlockDevice{SnapshotId: aws.String("snap-0e5f4a3b2c1d00756")}}},
		}},
		Addresses: []ec2types.Address{
			address("eipalloc-0a1b2c3d4e5f60718", "203.0.113.24", "old-vpn-endpoint", ""),
			address("eipalloc-0b2c3d4e5f6a71829", "203.0.113.57", "", ""),
			address("eipalloc-0c3d4e5f6a7b8293a", "203.0.113.90", "prod-api", "eipassoc-0d4e5f6a7b8c9304b"),
			address("eipalloc-0d4e5f6a7b8c9304b", "203.0.113.11", "prod-nat", "eipassoc-0e5f6a7b8c9d0415c"),
			address("eipalloc-0e5f6a7b8c9d0415c", "203.0.113.12", "staging-nat", "eipassoc-0f6a7b8c9d0e1526d"),
		},
		NatGateways: []ec2types.NatGateway{
			b.nat("nat-0a1b2c3d4e5f60789", "prod-nat-1a", vpc, "subnet-0a1b2c3d4e5f60789", "eipalloc-0d4e5f6a7b8c9304b", 690),
			b.nat("nat-0b2c3d4e5f6a7189a", "staging-nat-1c", vpc, "subnet-0b2c3d4e5f6a7189a", "eipalloc-0e5f6a7b8c9d0415c", 430),
		},
		SecurityGroups: []ec2types.SecurityGroup{
			securityGroup("sg-0a1b2c3d4e5f60718", "legacy-bastion", vpc, ingress(22, "0.0.0.0/0"), ingress(22, "::/0")),
			securityGroup("sg-0b2c3d4e5f6a71829", "db-debug-temp", vpc, ingress(5432, "0.0.0.0/0")),
			securityGroup("sg-0c3d4e5f6a7b8293a", "prod-web-alb", vpc, ingress(443, "0.0.0.0/0"), ingress(80, "0.0.0.0/0")),
			securityGroup("sg-0d4e5f6a7b8c9304b", "prod-db", vpc, ingress(5432, "10.20.0.0/16")),
		},
	}

	cw := &fakeaws.CloudWatch{Sums: map[fakeaws.MetricKey][]float64{
		{Namespace: "AWS/NATGateway", Metric: "BytesOutToDestination", Dimension: "nat-0a1b2c3d4e5f60789"}:    daily(1.9e12),
		{Namespace: "AWS/NATGateway", Metric: "BytesOutToDestination", Dimension: "nat-0b2c3d4e5f6a7189a"}:    daily(184 * 1024 * 1024),
		{Namespace: "AWS/ApplicationELB", Metric: "RequestCount", Dimension: "app/prod-web/5f3a8c1e9b7d2046"}: daily(48_000_000),
		{Namespace: "AWS/NetworkELB", Metric: "NewFlowCount", Dimension: "net/legacy-mqtt/3c7e1a9f5b2d8064"}:  daily(14),
	}}

	elb := &fakeaws.ELBv2{
		LoadBalancers: []elbtypes.LoadBalancer{
			b.loadBalancer(webALB, "prod-web", elbtypes.LoadBalancerTypeEnumApplication, r, 690),
			b.loadBalancer(stagingALB, "staging-web", elbtypes.LoadBalancerTypeEnumApplication, r, 430),
			b.loadBalancer(mqttNLB, "legacy-mqtt", elbtypes.LoadBalancerTypeEnumNetwork, r, 905),
		},
		TargetGroups: []elbtypes.TargetGroup{tgWeb, tgStaging, tgMQTT},
		TargetHealth: map[string][]elbtypes.TargetHealthDescription{
			*tgWeb.TargetGroupArn:     targets(elbtypes.TargetHealthStateEnumHealthy, elbtypes.TargetHealthStateEnumHealthy, elbtypes.TargetHealthStateEnumHealthy),
			*tgStaging.TargetGroupArn: targets(elbtypes.TargetHealthStateEnumUnhealthy),
			*tgMQTT.TargetGroupArn:    targets(elbtypes.TargetHealthStateEnumHealthy),
		},
	}

	rds := &fakeaws.RDS{DBInstances: []rdstypes.DBInstance{
		dbInstance(r, "prod-orders", "postgres", "db.r6g.large", 500, true, false),
		dbInstance(r, "reporting-replica", "mysql", "db.t3.medium", 200, false, true),
	}}

	return awsapi.Clients{EC2: ec2, CloudWatch: cw, ELBv2: elb, RDS: rds}
}

// singapore is the disaster-recovery region, set up once and rarely looked at.
func (b *Backend) singapore() awsapi.Clients {
	const vpc = "vpc-0b8d0f2c4e6a81357"
	const r = singapore
	drALB := lbARN(r, "app", "dr-failover", "6a4c2e0b8d1f3957")
	tgDR := targetGroup(r, "dr-failover", drALB)

	ec2 := &fakeaws.EC2{
		EBSEncryptionByDefault: false,
		Volumes: []ec2types.Volume{
			b.volume("vol-03c4d5e6f7a8b92a3", "log-archive-2023", 2000, ec2types.VolumeTypeSt1, 701, ""),
			b.volume("vol-04d5e6f7a8b9c03b4", "dr-app-data", 300, ec2types.VolumeTypeGp2, 610, "i-0e56f78a90b12c345"),
			b.volume("vol-05e6f7a8b9c0d14c5", "dr-app-root", 30, ec2types.VolumeTypeGp3, 610, "i-0e56f78a90b12c345"),
		},
		Instances: []ec2types.Instance{
			b.instance("i-0e56f78a90b12c345", "dr-app", ec2types.InstanceTypeT3Medium, ec2types.InstanceStateNameRunning, 0, "vol-05e6f7a8b9c0d14c5", "vol-04d5e6f7a8b9c03b4"),
		},
		Snapshots: []ec2types.Snapshot{
			b.snapshot("snap-02c3d4e5f6a7b8089", "vol-ffffffff", "Copied for DestinationAmi from ap-northeast-1", 800, 395),
			b.snapshot("snap-03d4e5f6a7b8c9190", "vol-04d5e6f7a8b9c03b4", "dr-app-data weekly", 300, 160),
		},
		Addresses: []ec2types.Address{
			address("eipalloc-0f6a7b8c9d0e1526d", "198.51.100.33", "dr-standby", ""),
			address("eipalloc-01a2b3c4d5e6f7a8b", "198.51.100.34", "dr-nat", "eipassoc-02b3c4d5e6f7a8b9c"),
		},
		NatGateways: []ec2types.NatGateway{
			b.nat("nat-0c3d4e5f6a7b8290b", "dr-nat-1a", vpc, "subnet-0c3d4e5f6a7b8290b", "eipalloc-01a2b3c4d5e6f7a8b", 610),
		},
		SecurityGroups: []ec2types.SecurityGroup{
			securityGroup("sg-0e5f6a7b8c9d0415c", "vendor-temp-access", vpc, ec2types.IpPermission{
				IpProtocol: aws.String("-1"), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0"), Description: aws.String("vendor debugging, remove after go-live")}},
			}),
			securityGroup("sg-0f6a7b8c9d0e1526d", "dr-app", vpc, ingress(443, "0.0.0.0/0")),
		},
	}
	cw := &fakeaws.CloudWatch{Sums: map[fakeaws.MetricKey][]float64{
		{Namespace: "AWS/NATGateway", Metric: "BytesOutToDestination", Dimension: "nat-0c3d4e5f6a7b8290b"}: daily(22 * 1024 * 1024),
	}}
	elb := &fakeaws.ELBv2{
		LoadBalancers: []elbtypes.LoadBalancer{b.loadBalancer(drALB, "dr-failover", elbtypes.LoadBalancerTypeEnumApplication, r, 600)},
		TargetGroups:  []elbtypes.TargetGroup{tgDR},
		TargetHealth:  map[string][]elbtypes.TargetHealthDescription{},
	}
	rds := &fakeaws.RDS{DBInstances: []rdstypes.DBInstance{
		dbInstance(r, "legacy-mysql-dr", "mysql", "db.t3.small", 100, false, false),
	}}
	return awsapi.Clients{EC2: ec2, CloudWatch: cw, ELBv2: elb, RDS: rds}
}

// globalData is the account-wide state: IAM, S3 and CloudTrail.
func (b *Backend) globalData() globalServices {
	at := func(days int) time.Time { return *b.ago(days) }
	alice, bob, contractor := b.user("alice", 900), b.user("bob", 640), b.user("contractor-dev", 75)
	ci, backup, tf := b.user("ci-deploy", 800), b.user("backup-script", 700), b.user("terraform", 300)
	alice.PasswordLastUsed, bob.PasswordLastUsed = b.ago(1), b.ago(3)

	iam := &fakeaws.IAM{
		Users:         []iamtypes.User{alice, bob, contractor, ci, backup, tf},
		LoginProfiles: map[string]time.Time{"alice": at(900), "bob": at(640), "contractor-dev": at(75)},
		MFADevices: map[string][]iamtypes.MFADevice{
			"alice": {{SerialNumber: aws.String("arn:aws:iam::" + AccountID + ":mfa/alice"), EnableDate: b.ago(880)}},
		},
		AccessKeys: map[string][]iamtypes.AccessKeyMetadata{
			"ci-deploy":     {b.key("AKIAIOSFODNN7EXAMPLE", 412)},
			"backup-script": {b.key("AKIAI44QH8DHBEXAMPLE", 650)},
			"terraform":     {b.key("AKIAJEXAMPLETERRAFRM", 40)},
		},
		KeyLastUsed: map[string]time.Time{
			"AKIAIOSFODNN7EXAMPLE": at(0),
			"AKIAI44QH8DHBEXAMPLE": at(203),
			"AKIAJEXAMPLETERRAFRM": at(2),
		},
		Summary: map[string]int32{"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 1, "Users": 6},
	}

	partial := s3types.PublicAccessBlockConfiguration{BlockPublicAcls: aws.Bool(true), IgnorePublicAcls: aws.Bool(true), BlockPublicPolicy: aws.Bool(false), RestrictPublicBuckets: aws.Bool(false)}
	full := s3types.PublicAccessBlockConfiguration{BlockPublicAcls: aws.Bool(true), IgnorePublicAcls: aws.Bool(true), BlockPublicPolicy: aws.Bool(true), RestrictPublicBuckets: aws.Bool(true)}
	s3 := &fakeaws.S3{
		Buckets: []s3types.Bucket{
			bucket("examplecorp-prod-assets", tokyo),
			bucket("examplecorp-marketing-site", tokyo),
			bucket("examplecorp-data-exports", singapore),
			bucket("examplecorp-terraform-state", tokyo),
		},
		PublicAccessBlocks: map[string]s3types.PublicAccessBlockConfiguration{
			"examplecorp-prod-assets":     full,
			"examplecorp-data-exports":    partial,
			"examplecorp-terraform-state": full,
		},
	}

	ct := &fakeaws.CloudTrail{
		Trails:  []cttypes.Trail{trail("tokyo-only-trail", tokyo, false)},
		Logging: map[string]bool{},
	}
	return globalServices{iam: iam, s3: s3, s3control: &fakeaws.S3Control{}, cloudtrail: ct}
}
