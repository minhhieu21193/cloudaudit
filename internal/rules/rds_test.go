package rules

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/minhhieu21193/cloudaudit/internal/fakeaws"
)

func db(id string, encrypted, public bool) rdstypes.DBInstance {
	return rdstypes.DBInstance{
		DBInstanceIdentifier: aws.String(id), Engine: aws.String("postgres"), DBInstanceClass: aws.String("db.t3.medium"),
		StorageEncrypted: aws.Bool(encrypted), PubliclyAccessible: aws.Bool(public), AllocatedStorage: aws.Int32(100),
		Endpoint: &rdstypes.Endpoint{Address: aws.String(id + ".example.rds.amazonaws.com"), Port: aws.Int32(5432)},
	}
}

func rdsFake() *fakeaws.RDS {
	aurora := db("aurora-1", false, false)
	aurora.DBClusterIdentifier = aws.String("orders-cluster")
	return &fakeaws.RDS{DBInstances: []rdstypes.DBInstance{
		db("good", true, false),
		db("plain", false, false),
		db("exposed", true, true),
		db("worst", false, true),
		aurora,
	}}
}

func TestRDSUnencrypted(t *testing.T) {
	got, err := RDSUnencrypted{}.scan(context.Background(), rdsFake(), testEnv("us-east-1"))
	if err != nil {
		t.Fatal(err)
	}
	m := byResource(t, got)
	if len(m) != 3 || m["plain"].ResourceID == "" || m["worst"].ResourceID == "" {
		t.Fatalf("got %v, want plain, worst, aurora-1", m)
	}
	if !strings.Contains(m["plain"].FixCommand, "copy-db-snapshot") || !strings.Contains(m["plain"].FixCommand, "--kms-key-id") {
		t.Errorf("plain fix = %q", m["plain"].FixCommand)
	}
	if !strings.Contains(m["aurora-1"].FixCommand, "create-db-cluster-snapshot --region us-east-1 --db-cluster-identifier orders-cluster") {
		t.Errorf("aurora fix = %q", m["aurora-1"].FixCommand)
	}
}

func TestRDSPublic(t *testing.T) {
	got, err := RDSPublic{}.scan(context.Background(), rdsFake(), testEnv("us-east-1"))
	if err != nil {
		t.Fatal(err)
	}
	m := byResource(t, got)
	if len(m) != 2 || m["exposed"].ResourceID == "" || m["worst"].ResourceID == "" {
		t.Fatalf("got %v, want exposed, worst", m)
	}
	if !strings.Contains(m["exposed"].Evidence, "exposed.example.rds.amazonaws.com:5432") {
		t.Errorf("evidence = %q", m["exposed"].Evidence)
	}
	if !strings.Contains(m["exposed"].FixCommand, "--no-publicly-accessible") {
		t.Errorf("fix = %q", m["exposed"].FixCommand)
	}
}

func TestRDSError(t *testing.T) {
	if _, err := (RDSPublic{}).scan(context.Background(), &fakeaws.RDS{Err: errors.New("AccessDenied")}, testEnv("us-east-1")); err == nil {
		t.Fatal("expected error")
	}
}
