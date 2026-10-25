package pricing

import (
	"math"
	"testing"
)

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestForKnownRegion(t *testing.T) {
	p, exact := For("ap-northeast-1")
	if !exact {
		t.Fatal("ap-northeast-1 should be in the table")
	}
	if got := p.EBSMonthly("gp3", 100); !approx(got, 9.6) {
		t.Errorf("gp3 100 GiB = %v, want 9.6", got)
	}
	if got := Monthly(p.NATGatewayHour); !approx(got, 45.26) {
		t.Errorf("NAT monthly = %v, want 45.26", got)
	}
}

func TestForUnknownRegionFallsBack(t *testing.T) {
	p, exact := For("me-central-1")
	if exact {
		t.Fatal("me-central-1 is not in the table; exact should be false")
	}
	def, _ := For(DefaultRegion)
	if !approx(p.NATGatewayHour, def.NATGatewayHour) {
		t.Errorf("fallback NAT price = %v, want %v", p.NATGatewayHour, def.NATGatewayHour)
	}
}

func TestEBSMonthlyUnknownTypeUsesGP2(t *testing.T) {
	p, _ := For("us-east-1")
	if got := p.EBSMonthly("future-type", 10); !approx(got, 1.0) {
		t.Errorf("unknown type 10 GiB = %v, want 1.0 (gp2 rate)", got)
	}
}

func TestTableIsComplete(t *testing.T) {
	for region, p := range table {
		for _, vt := range []string{"gp2", "gp3", "io1", "io2", "st1", "sc1", "standard"} {
			if p.EBSGBMonth[vt] <= 0 {
				t.Errorf("%s: missing EBS price for %s", region, vt)
			}
		}
		if p.EBSGBMonth["gp3"] >= p.EBSGBMonth["gp2"] {
			t.Errorf("%s: gp3 should be cheaper than gp2", region)
		}
		for name, v := range map[string]float64{
			"snapshot": p.SnapshotGBMonth, "ipv4": p.PublicIPv4Hour, "nat": p.NATGatewayHour,
			"alb": p.ApplicationLBHour, "nlb": p.NetworkLBHour,
		} {
			if v <= 0 {
				t.Errorf("%s: missing %s price", region, name)
			}
		}
	}
}
