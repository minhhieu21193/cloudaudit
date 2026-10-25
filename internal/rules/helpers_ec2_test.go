package rules

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/minhhieu21193/cloudaudit/internal/fakeaws"
)

func vol(id string, sizeGiB int32, vt ec2types.VolumeType, state ec2types.VolumeState, instanceID string) ec2types.Volume {
	v := ec2types.Volume{VolumeId: aws.String(id), Size: aws.Int32(sizeGiB), VolumeType: vt, State: state, CreateTime: aws.Time(daysAgo(400))}
	if instanceID != "" {
		v.Attachments = []ec2types.VolumeAttachment{{InstanceId: aws.String(instanceID), VolumeId: aws.String(id)}}
	}
	return v
}

func newStoppedInstance(id, reason string, volumeIDs ...string) ec2types.Instance {
	inst := ec2types.Instance{
		InstanceId:            aws.String(id),
		InstanceType:          ec2types.InstanceTypeM5Large,
		State:                 &ec2types.InstanceState{Name: ec2types.InstanceStateNameStopped},
		StateTransitionReason: aws.String(reason),
	}
	for _, v := range volumeIDs {
		inst.BlockDeviceMappings = append(inst.BlockDeviceMappings, ec2types.InstanceBlockDeviceMapping{
			Ebs: &ec2types.EbsInstanceBlockDevice{VolumeId: aws.String(v)},
		})
	}
	return inst
}

func TestEC2ChecksPropagateErrors(t *testing.T) {
	fake := &fakeaws.EC2{Err: errors.New("UnauthorizedOperation")}
	env := testEnv("us-east-1")
	ctx := context.Background()
	for name, run := range map[string]func() error{
		"eip":      func() error { _, err := EIPUnassociated{}.scan(ctx, fake, env); return err },
		"stopped":  func() error { _, err := EC2Stopped{}.scan(ctx, fake, env); return err },
		"gp2":      func() error { _, err := EBSGP2ToGP3{}.scan(ctx, fake, env); return err },
		"snapshot": func() error { _, err := EBSSnapshotOrphaned{}.scan(ctx, fake, env); return err },
	} {
		if err := run(); err == nil || !strings.Contains(err.Error(), "UnauthorizedOperation") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
