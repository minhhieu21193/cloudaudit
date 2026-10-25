package rules

import (
	"context"
	"testing"

	"github.com/minhhieu21193/cloudaudit/internal/checks"
	"github.com/minhhieu21193/cloudaudit/internal/fakeaws"
)

func TestRootAccount(t *testing.T) {
	tests := []struct {
		name    string
		summary map[string]int32
		want    []string
	}{
		{"healthy", map[string]int32{"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}, nil},
		{"keys and no MFA", map[string]int32{"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 1}, []string{"root/access-keys", "root/mfa"}},
		{"no MFA only", map[string]int32{"AccountMFAEnabled": 0}, []string{"root/mfa"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RootAccount{}.scan(context.Background(), &fakeaws.IAM{Summary: tt.summary}, testEnv(checks.GlobalRegion))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %+v, want %v", got, tt.want)
			}
			for i, id := range tt.want {
				if got[i].ResourceID != id || got[i].Severity != checks.SeverityCritical {
					t.Errorf("finding %d = %+v, want CRITICAL %s", i, got[i], id)
				}
			}
		})
	}
}
