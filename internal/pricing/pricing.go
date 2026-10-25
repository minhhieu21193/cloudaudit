// Package pricing is a small, static table of on-demand list prices (USD)
// used to estimate monthly waste. cloudaudit never calls the AWS Pricing API;
// every figure derived from this table is an estimate and is labelled as one
// in the reports. It ignores free tier, Savings Plans, EDP discounts, IOPS and
// throughput charges, and data processing/transfer.
//
// Source: AWS Price List bulk offer files, extracted 2026-10-25.
//   - EBS volumes, EBS snapshots, NAT Gateway hours: AmazonEC2 offer,
//     publication 2026-10-23,
//     https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonEC2/current/<region>/index.csv
//   - Public IPv4 addresses: AmazonVPC offer, publication 2026-10-16,
//     https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonVPC/current/<region>/index.json
//   - ALB / NLB hours: AWSELB offer, publication 2026-09-11,
//     https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSELB/current/<region>/index.json
//
// Human-readable equivalents: https://aws.amazon.com/ebs/pricing/,
// https://aws.amazon.com/vpc/pricing/, https://aws.amazon.com/elasticloadbalancing/pricing/
package pricing

// HoursPerMonth is the 730-hour month AWS uses on its pricing pages.
const HoursPerMonth = 730

// DefaultRegion supplies prices for regions missing from the table.
const DefaultRegion = "us-east-1"

type Prices struct {
	// EBSGBMonth is storage only, keyed by EC2 volume type (gp2, gp3, ...).
	EBSGBMonth        map[string]float64
	SnapshotGBMonth   float64
	PublicIPv4Hour    float64
	NATGatewayHour    float64
	ApplicationLBHour float64
	NetworkLBHour     float64
}

var table = map[string]Prices{
	"us-east-1": {
		EBSGBMonth:        map[string]float64{"gp2": 0.10, "gp3": 0.08, "io1": 0.125, "io2": 0.125, "st1": 0.045, "sc1": 0.015, "standard": 0.05},
		SnapshotGBMonth:   0.05,
		PublicIPv4Hour:    0.005,
		NATGatewayHour:    0.045,
		ApplicationLBHour: 0.0225,
		NetworkLBHour:     0.0225,
	},
	"us-west-2": {
		EBSGBMonth:        map[string]float64{"gp2": 0.10, "gp3": 0.08, "io1": 0.125, "io2": 0.125, "st1": 0.045, "sc1": 0.015, "standard": 0.05},
		SnapshotGBMonth:   0.05,
		PublicIPv4Hour:    0.005,
		NATGatewayHour:    0.045,
		ApplicationLBHour: 0.0225,
		NetworkLBHour:     0.0225,
	},
	"eu-west-1": {
		EBSGBMonth:        map[string]float64{"gp2": 0.11, "gp3": 0.088, "io1": 0.138, "io2": 0.138, "st1": 0.05, "sc1": 0.0168, "standard": 0.055},
		SnapshotGBMonth:   0.05,
		PublicIPv4Hour:    0.005,
		NATGatewayHour:    0.048,
		ApplicationLBHour: 0.0252,
		NetworkLBHour:     0.0252,
	},
	"ap-northeast-1": {
		EBSGBMonth:        map[string]float64{"gp2": 0.12, "gp3": 0.096, "io1": 0.142, "io2": 0.142, "st1": 0.054, "sc1": 0.018, "standard": 0.08},
		SnapshotGBMonth:   0.05,
		PublicIPv4Hour:    0.005,
		NATGatewayHour:    0.062,
		ApplicationLBHour: 0.0243,
		NetworkLBHour:     0.0243,
	},
	"ap-southeast-1": {
		EBSGBMonth:        map[string]float64{"gp2": 0.12, "gp3": 0.096, "io1": 0.138, "io2": 0.138, "st1": 0.054, "sc1": 0.018, "standard": 0.08},
		SnapshotGBMonth:   0.05,
		PublicIPv4Hour:    0.005,
		NATGatewayHour:    0.059,
		ApplicationLBHour: 0.0252,
		NetworkLBHour:     0.0252,
	},
}

// For returns the prices for region. exact is false when the region is not
// in the table and DefaultRegion prices were used instead.
func For(region string) (p Prices, exact bool) {
	if p, ok := table[region]; ok {
		return p, true
	}
	return table[DefaultRegion], false
}

// EBSMonthly is the storage cost of a volume. Unknown volume types are
// priced as gp2, the most common legacy type.
func (p Prices) EBSMonthly(volumeType string, sizeGiB int32) float64 {
	rate, ok := p.EBSGBMonth[volumeType]
	if !ok {
		rate = p.EBSGBMonth["gp2"]
	}
	return rate * float64(sizeGiB)
}

func (p Prices) SnapshotMonthly(sizeGiB int32) float64 {
	return p.SnapshotGBMonth * float64(sizeGiB)
}

func Monthly(hourly float64) float64 {
	return hourly * HoursPerMonth
}
