package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

type Client struct {
	Ec2 *ec2.Client
}

func NewClient(profile string) (*Client, error) {

	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithSharedConfigProfile(profile))
	if err != nil {
		return nil, err
	}
	return &Client{
		Ec2: ec2.NewFromConfig(cfg),
	}, nil
}
