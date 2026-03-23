package check

import (
	"context"

	awsclient "github.com/minhhieu21193/cloudaudit/internal/aws"
)

type Finding struct {
	Title          string
	Severity       string
	Description    string
	MonthlySavings float64
	Recommendation string
	FixCommand     string
}

type Check interface {
	Run(ctx context.Context, client *awsclient.Client) ([]Finding, error)
}
