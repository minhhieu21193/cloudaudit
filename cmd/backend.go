package cmd

import (
	"context"

	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
	"github.com/minhhieu21193/cloudaudit/internal/awsclient"
)

// backend is where a scan gets its account identity, regions and clients:
// real AWS, or the built-in demo data.
type backend interface {
	AccountID(ctx context.Context) (string, error)
	DefaultRegion() string
	EnabledRegions(ctx context.Context) ([]string, error)
	Clients(ctx context.Context, region string) (awsapi.Clients, error)
}

// isDemo reports whether b serves built-in sample data, which the report
// must say prominently.
func isDemo(b backend) bool {
	d, ok := b.(interface{ Demo() bool })
	return ok && d.Demo()
}

type backendFactory func(ctx context.Context, o *scanOptions) (backend, error)

func defaultBackend(ctx context.Context, o *scanOptions) (backend, error) {
	return awsclient.Load(ctx, awsclient.Options{
		Profile:    o.profile,
		RoleARN:    o.roleARN,
		ExternalID: o.externalID,
	})
}
