// Package demo is a fictional AWS account used by `cloudaudit scan --demo`.
// It runs every check against in-memory fakes, so the tool can be tried and
// the sample report regenerated without credentials. Every ID and name here
// is made up; 123456789012 is the placeholder account ID AWS uses in its
// documentation. Timestamps are relative to the scan time so the sample
// never goes stale.
package demo

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
	"github.com/minhhieu21193/cloudaudit/internal/fakeaws"
)

const (
	AccountID = "123456789012"
	tokyo     = "ap-northeast-1"
	singapore = "ap-southeast-1"
)

// Regions are the regions the demo account has resources in.
var Regions = []string{tokyo, singapore}

type Backend struct {
	now     time.Time
	regions map[string]awsapi.Clients
	global  globalServices
}

type globalServices struct {
	iam        *fakeaws.IAM
	s3         *fakeaws.S3
	s3control  *fakeaws.S3Control
	cloudtrail *fakeaws.CloudTrail
}

// New builds the demo account as it looks at now.
func New(now time.Time) *Backend {
	b := &Backend{now: now.UTC()}
	b.global = b.globalData()
	b.regions = map[string]awsapi.Clients{
		tokyo:     b.withGlobal(b.tokyo()),
		singapore: b.withGlobal(b.singapore()),
	}
	return b
}

func (b *Backend) Demo() bool { return true }

func (b *Backend) AccountID(context.Context) (string, error) { return AccountID, nil }

func (b *Backend) DefaultRegion() string { return tokyo }

func (b *Backend) EnabledRegions(context.Context) ([]string, error) {
	return append([]string(nil), Regions...), nil
}

// Clients returns the fakes for region. Regions outside the demo account are
// empty but valid, like a real region with no resources.
func (b *Backend) Clients(_ context.Context, region string) (awsapi.Clients, error) {
	if c, ok := b.regions[region]; ok {
		return c, nil
	}
	return b.withGlobal(awsapi.Clients{
		EC2:        &fakeaws.EC2{EBSEncryptionByDefault: true},
		CloudWatch: &fakeaws.CloudWatch{},
		ELBv2:      &fakeaws.ELBv2{},
		RDS:        &fakeaws.RDS{},
	}), nil
}

func (b *Backend) withGlobal(c awsapi.Clients) awsapi.Clients {
	c.IAM = b.global.iam
	c.S3 = b.global.s3
	c.S3Control = b.global.s3control
	c.CloudTrail = b.global.cloudtrail
	return c
}

func (b *Backend) ago(days int) *time.Time {
	t := b.now.Add(-time.Duration(days) * 24 * time.Hour).Truncate(time.Minute)
	return &t
}

// stopReason mimics EC2's StateTransitionReason.
func (b *Backend) stopReason(days int) *string {
	return aws.String(fmt.Sprintf("User initiated (%s GMT)", b.ago(days).Format("2006-01-02 15:04:05")))
}

func tags(name string) []ec2types.Tag {
	return []ec2types.Tag{{Key: aws.String("Name"), Value: aws.String(name)}}
}

func (b *Backend) volume(id, name string, size int32, vt ec2types.VolumeType, ageDays int, instanceID string) ec2types.Volume {
	v := ec2types.Volume{
		VolumeId: aws.String(id), Size: aws.Int32(size), VolumeType: vt,
		State: ec2types.VolumeStateAvailable, CreateTime: b.ago(ageDays), Tags: tags(name),
	}
	if instanceID != "" {
		v.State = ec2types.VolumeStateInUse
		v.Attachments = []ec2types.VolumeAttachment{{InstanceId: aws.String(instanceID), VolumeId: aws.String(id), State: ec2types.VolumeAttachmentStateAttached}}
	}
	return v
}

func (b *Backend) instance(id, name string, it ec2types.InstanceType, state ec2types.InstanceStateName, stoppedDays int, volumeIDs ...string) ec2types.Instance {
	inst := ec2types.Instance{
		InstanceId: aws.String(id), InstanceType: it, Tags: tags(name),
		State: &ec2types.InstanceState{Name: state}, StateTransitionReason: aws.String(""),
	}
	if state == ec2types.InstanceStateNameStopped {
		inst.StateTransitionReason = b.stopReason(stoppedDays)
	}
	for _, v := range volumeIDs {
		inst.BlockDeviceMappings = append(inst.BlockDeviceMappings, ec2types.InstanceBlockDeviceMapping{Ebs: &ec2types.EbsInstanceBlockDevice{VolumeId: aws.String(v)}})
	}
	return inst
}

func (b *Backend) snapshot(id, volumeID, desc string, size int32, ageDays int) ec2types.Snapshot {
	return ec2types.Snapshot{
		SnapshotId: aws.String(id), VolumeId: aws.String(volumeID), VolumeSize: aws.Int32(size),
		StartTime: b.ago(ageDays), Description: aws.String(desc), State: ec2types.SnapshotStateCompleted,
		OwnerId: aws.String(AccountID),
	}
}

func address(allocID, ip, name, assocID string) ec2types.Address {
	a := ec2types.Address{AllocationId: aws.String(allocID), PublicIp: aws.String(ip), Domain: ec2types.DomainTypeVpc, Tags: tags(name)}
	if assocID != "" {
		a.AssociationId = aws.String(assocID)
		a.InstanceId = aws.String("i-0f1e2d3c4b5a69788")
	}
	return a
}

func (b *Backend) nat(id, name, vpc, subnet, allocID string, ageDays int) ec2types.NatGateway {
	return ec2types.NatGateway{
		NatGatewayId: aws.String(id), State: ec2types.NatGatewayStateAvailable, CreateTime: b.ago(ageDays),
		VpcId: aws.String(vpc), SubnetId: aws.String(subnet), Tags: tags(name),
		NatGatewayAddresses: []ec2types.NatGatewayAddress{{AllocationId: aws.String(allocID)}},
	}
}

func ingress(port int32, cidr string) ec2types.IpPermission {
	p := ec2types.IpPermission{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(port), ToPort: aws.Int32(port)}
	if cidr == "::/0" {
		p.Ipv6Ranges = []ec2types.Ipv6Range{{CidrIpv6: aws.String(cidr)}}
	} else {
		p.IpRanges = []ec2types.IpRange{{CidrIp: aws.String(cidr)}}
	}
	return p
}

func securityGroup(id, name, vpc string, perms ...ec2types.IpPermission) ec2types.SecurityGroup {
	return ec2types.SecurityGroup{GroupId: aws.String(id), GroupName: aws.String(name), VpcId: aws.String(vpc), IpPermissions: perms}
}

func lbARN(region, kind, name, suffix string) string {
	return fmt.Sprintf("arn:aws:elasticloadbalancing:%s:%s:loadbalancer/%s/%s/%s", region, AccountID, kind, name, suffix)
}

func (b *Backend) loadBalancer(arn, name string, t elbtypes.LoadBalancerTypeEnum, region string, ageDays int) elbtypes.LoadBalancer {
	return elbtypes.LoadBalancer{
		LoadBalancerArn: aws.String(arn), LoadBalancerName: aws.String(name), Type: t, CreatedTime: b.ago(ageDays),
		Scheme: elbtypes.LoadBalancerSchemeEnumInternetFacing, DNSName: aws.String(fmt.Sprintf("%s-1234567890.%s.elb.amazonaws.com", name, region)),
	}
}

func targetGroup(region, name, lbArn string) elbtypes.TargetGroup {
	return elbtypes.TargetGroup{
		TargetGroupArn:   aws.String(fmt.Sprintf("arn:aws:elasticloadbalancing:%s:%s:targetgroup/%s/0a1b2c3d4e5f6a7b", region, AccountID, name)),
		TargetGroupName:  aws.String(name),
		LoadBalancerArns: []string{lbArn},
	}
}

func targets(states ...elbtypes.TargetHealthStateEnum) []elbtypes.TargetHealthDescription {
	out := make([]elbtypes.TargetHealthDescription, 0, len(states))
	for i, s := range states {
		out = append(out, elbtypes.TargetHealthDescription{
			Target:       &elbtypes.TargetDescription{Id: aws.String(fmt.Sprintf("i-0aa%014d", i))},
			TargetHealth: &elbtypes.TargetHealth{State: s},
		})
	}
	return out
}

// daily spreads total evenly over the checks' default lookback window.
func daily(total float64) []float64 {
	days := checks.DefaultConfig().IdleLookbackDays
	out := make([]float64, days)
	for i := range out {
		out[i] = total / float64(days)
	}
	return out
}

func dbInstance(region, id, engine, class string, storage int32, encrypted, public bool) rdstypes.DBInstance {
	return rdstypes.DBInstance{
		DBInstanceIdentifier: aws.String(id), Engine: aws.String(engine), DBInstanceClass: aws.String(class),
		AllocatedStorage: aws.Int32(storage), StorageEncrypted: aws.Bool(encrypted), PubliclyAccessible: aws.Bool(public),
		DBInstanceArn:    aws.String(fmt.Sprintf("arn:aws:rds:%s:%s:db:%s", region, AccountID, id)),
		DBInstanceStatus: aws.String("available"),
		Endpoint:         &rdstypes.Endpoint{Address: aws.String(fmt.Sprintf("%s.c1a2b3c4d5e6.%s.rds.amazonaws.com", id, region)), Port: aws.Int32(dbPort(engine))},
	}
}

func dbPort(engine string) int32 {
	if engine == "postgres" {
		return 5432
	}
	return 3306
}

func (b *Backend) user(name string, createdDaysAgo int) iamtypes.User {
	return iamtypes.User{
		UserName:   aws.String(name),
		UserId:     aws.String("AIDA" + fmt.Sprintf("%016X", len(name)*7919)),
		Arn:        aws.String(fmt.Sprintf("arn:aws:iam::%s:user/%s", AccountID, name)),
		CreateDate: b.ago(createdDaysAgo),
	}
}

func (b *Backend) key(id string, createdDaysAgo int) iamtypes.AccessKeyMetadata {
	return iamtypes.AccessKeyMetadata{AccessKeyId: aws.String(id), CreateDate: b.ago(createdDaysAgo), Status: iamtypes.StatusTypeActive}
}

func bucket(name, region string) s3types.Bucket {
	return s3types.Bucket{Name: aws.String(name), BucketRegion: aws.String(region)}
}

func trail(name, region string, multi bool) cttypes.Trail {
	return cttypes.Trail{
		Name: aws.String(name), HomeRegion: aws.String(region), IsMultiRegionTrail: aws.Bool(multi),
		TrailARN: aws.String(fmt.Sprintf("arn:aws:cloudtrail:%s:%s:trail/%s", region, AccountID, name)),
	}
}
