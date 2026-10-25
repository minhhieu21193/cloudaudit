// Package rules contains the individual audit checks. Each check lives in its
// own file, depends only on the narrow awsapi interfaces it calls, and is
// unit-tested with fakes.
package rules

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
	"github.com/minhhieu21193/cloudaudit/internal/pricing"
)

// All returns every check in a stable order.
func All() []checks.Check {
	return []checks.Check{
		EBSUnattached{},
		EBSGP2ToGP3{},
		EBSSnapshotOrphaned{},
		EIPUnassociated{},
		EC2Stopped{},
	}
}

// costSeverity ranks cost findings by estimated monthly waste.
func costSeverity(usd float64) checks.Severity {
	switch {
	case usd >= 100:
		return checks.SeverityHigh
	case usd >= 20:
		return checks.SeverityMedium
	default:
		return checks.SeverityLow
	}
}

// priceNote is appended to evidence when the region's prices were not in the
// static table.
func priceNote(exact bool) string {
	if exact {
		return ""
	}
	return fmt.Sprintf(" Priced with %s rates (region not in price table).", pricing.DefaultRegion)
}

func ec2Name(tags []ec2types.Tag) string {
	for _, t := range tags {
		if aws.ToString(t.Key) == "Name" {
			return aws.ToString(t.Value)
		}
	}
	return ""
}

// withName renders "id (name)" when a Name tag exists.
func withName(id, name string) string {
	if name == "" {
		return id
	}
	return fmt.Sprintf("%s (%s)", id, name)
}
