// Package fakeaws provides in-memory implementations of the awsapi
// interfaces. Rule tests and the --demo mode use them in place of AWS. Each
// fake supports exactly the request filters the rules send and rejects any
// other filter, so a rule that changes its query fails loudly instead of
// silently matching everything.
package fakeaws

import (
	"context"
	"fmt"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
)

var _ awsapi.EC2 = (*EC2)(nil)

type EC2 struct {
	Regions                []string
	Volumes                []ec2types.Volume
	Addresses              []ec2types.Address
	Snapshots              []ec2types.Snapshot
	Images                 []ec2types.Image
	Instances              []ec2types.Instance
	NatGateways            []ec2types.NatGateway
	SecurityGroups         []ec2types.SecurityGroup
	EBSEncryptionByDefault bool
	// Err, when set, is returned by every call.
	Err error
}

func (f *EC2) DescribeRegions(context.Context, *ec2.DescribeRegionsInput, ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	out := &ec2.DescribeRegionsOutput{}
	for _, r := range f.Regions {
		out.Regions = append(out.Regions, ec2types.Region{RegionName: aws.String(r), OptInStatus: aws.String("opt-in-not-required")})
	}
	return out, nil
}

func (f *EC2) DescribeVolumes(_ context.Context, in *ec2.DescribeVolumesInput, _ ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	out := &ec2.DescribeVolumesOutput{}
	for _, v := range f.Volumes {
		ok, err := matchAll(in.Filters, func(name string) ([]string, error) {
			switch name {
			case "status":
				return []string{string(v.State)}, nil
			case "volume-type":
				return []string{string(v.VolumeType)}, nil
			case "volume-id":
				return []string{aws.ToString(v.VolumeId)}, nil
			}
			return nil, unsupported("DescribeVolumes", name)
		})
		if err != nil {
			return nil, err
		}
		if ok {
			out.Volumes = append(out.Volumes, v)
		}
	}
	return out, nil
}

func (f *EC2) DescribeAddresses(context.Context, *ec2.DescribeAddressesInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return &ec2.DescribeAddressesOutput{Addresses: f.Addresses}, nil
}

// DescribeSnapshots returns every snapshot; the fake holds only snapshots
// owned by the scanned account, so OwnerIds=self is implied.
func (f *EC2) DescribeSnapshots(_ context.Context, in *ec2.DescribeSnapshotsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	if len(in.Filters) > 0 {
		return nil, unsupported("DescribeSnapshots", aws.ToString(in.Filters[0].Name))
	}
	return &ec2.DescribeSnapshotsOutput{Snapshots: f.Snapshots}, nil
}

func (f *EC2) DescribeImages(_ context.Context, in *ec2.DescribeImagesInput, _ ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	if len(in.Filters) > 0 {
		return nil, unsupported("DescribeImages", aws.ToString(in.Filters[0].Name))
	}
	return &ec2.DescribeImagesOutput{Images: f.Images}, nil
}

func (f *EC2) DescribeInstances(_ context.Context, in *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	var matched []ec2types.Instance
	for _, inst := range f.Instances {
		ok, err := matchAll(in.Filters, func(name string) ([]string, error) {
			if name == "instance-state-name" && inst.State != nil {
				return []string{string(inst.State.Name)}, nil
			}
			return nil, unsupported("DescribeInstances", name)
		})
		if err != nil {
			return nil, err
		}
		if ok {
			matched = append(matched, inst)
		}
	}
	out := &ec2.DescribeInstancesOutput{}
	if len(matched) > 0 {
		out.Reservations = []ec2types.Reservation{{Instances: matched}}
	}
	return out, nil
}

func (f *EC2) DescribeNatGateways(_ context.Context, in *ec2.DescribeNatGatewaysInput, _ ...func(*ec2.Options)) (*ec2.DescribeNatGatewaysOutput, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	out := &ec2.DescribeNatGatewaysOutput{}
	for _, n := range f.NatGateways {
		ok, err := matchAll(in.Filter, func(name string) ([]string, error) {
			if name == "state" {
				return []string{string(n.State)}, nil
			}
			return nil, unsupported("DescribeNatGateways", name)
		})
		if err != nil {
			return nil, err
		}
		if ok {
			out.NatGateways = append(out.NatGateways, n)
		}
	}
	return out, nil
}

func (f *EC2) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: f.SecurityGroups}, nil
}

func (f *EC2) GetEbsEncryptionByDefault(context.Context, *ec2.GetEbsEncryptionByDefaultInput, ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return &ec2.GetEbsEncryptionByDefaultOutput{EbsEncryptionByDefault: aws.Bool(f.EBSEncryptionByDefault)}, nil
}

// matchAll reports whether a resource matches every filter. Values within a
// filter are ORed, filters are ANDed, as in the EC2 API.
func matchAll(filters []ec2types.Filter, field func(name string) ([]string, error)) (bool, error) {
	for _, flt := range filters {
		have, err := field(aws.ToString(flt.Name))
		if err != nil {
			return false, err
		}
		if !slices.ContainsFunc(have, func(h string) bool { return slices.Contains(flt.Values, h) }) {
			return false, nil
		}
	}
	return true, nil
}

func unsupported(op, filter string) error {
	return fmt.Errorf("fakeaws: %s filter %q is not supported", op, filter)
}
