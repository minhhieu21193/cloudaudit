package awsapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// allInterfaces must list every interface declared in this package. The
// test below parses the package source and fails if one is missing, so a new
// interface cannot skip the read-only check.
var allInterfaces = map[string]reflect.Type{
	"DescribeRegionsAPI":             reflect.TypeFor[DescribeRegionsAPI](),
	"DescribeVolumesAPI":             reflect.TypeFor[DescribeVolumesAPI](),
	"DescribeAddressesAPI":           reflect.TypeFor[DescribeAddressesAPI](),
	"DescribeSnapshotsAPI":           reflect.TypeFor[DescribeSnapshotsAPI](),
	"DescribeInstancesAPI":           reflect.TypeFor[DescribeInstancesAPI](),
	"DescribeNatGatewaysAPI":         reflect.TypeFor[DescribeNatGatewaysAPI](),
	"DescribeSecurityGroupsAPI":      reflect.TypeFor[DescribeSecurityGroupsAPI](),
	"GetEbsEncryptionByDefaultAPI":   reflect.TypeFor[GetEbsEncryptionByDefaultAPI](),
	"EC2":                            reflect.TypeFor[EC2](),
	"GetMetricStatisticsAPI":         reflect.TypeFor[GetMetricStatisticsAPI](),
	"CloudWatch":                     reflect.TypeFor[CloudWatch](),
	"DescribeLoadBalancersAPI":       reflect.TypeFor[DescribeLoadBalancersAPI](),
	"DescribeTargetGroupsAPI":        reflect.TypeFor[DescribeTargetGroupsAPI](),
	"DescribeTargetHealthAPI":        reflect.TypeFor[DescribeTargetHealthAPI](),
	"ELBv2":                          reflect.TypeFor[ELBv2](),
	"ListBucketsAPI":                 reflect.TypeFor[ListBucketsAPI](),
	"GetBucketPublicAccessBlockAPI":  reflect.TypeFor[GetBucketPublicAccessBlockAPI](),
	"S3":                             reflect.TypeFor[S3](),
	"GetAccountPublicAccessBlockAPI": reflect.TypeFor[GetAccountPublicAccessBlockAPI](),
	"S3Control":                      reflect.TypeFor[S3Control](),
	"ListUsersAPI":                   reflect.TypeFor[ListUsersAPI](),
	"GetLoginProfileAPI":             reflect.TypeFor[GetLoginProfileAPI](),
	"ListMFADevicesAPI":              reflect.TypeFor[ListMFADevicesAPI](),
	"ListAccessKeysAPI":              reflect.TypeFor[ListAccessKeysAPI](),
	"GetAccessKeyLastUsedAPI":        reflect.TypeFor[GetAccessKeyLastUsedAPI](),
	"GetAccountSummaryAPI":           reflect.TypeFor[GetAccountSummaryAPI](),
	"IAM":                            reflect.TypeFor[IAM](),
	"DescribeDBInstancesAPI":         reflect.TypeFor[DescribeDBInstancesAPI](),
	"RDS":                            reflect.TypeFor[RDS](),
	"DescribeTrailsAPI":              reflect.TypeFor[DescribeTrailsAPI](),
	"GetTrailStatusAPI":              reflect.TypeFor[GetTrailStatusAPI](),
	"CloudTrail":                     reflect.TypeFor[CloudTrail](),
}

var (
	allowedPrefixes   = []string{"Describe", "Get", "List"}
	forbiddenPrefixes = []string{
		"Create", "Delete", "Modify", "Put", "Update", "Attach", "Detach",
		"Generate", "Start", "Stop", "Terminate",
	}
)

// TestInterfacesAreReadOnly is the guarantee that cloudaudit cannot change
// a client's account: every AWS operation it can reach goes through these
// interfaces, and none of them may expose a mutating method.
func TestInterfacesAreReadOnly(t *testing.T) {
	for name, typ := range allInterfaces {
		if typ.Kind() != reflect.Interface {
			t.Errorf("%s is %s, want interface", name, typ.Kind())
			continue
		}
		for i := range typ.NumMethod() {
			method := typ.Method(i).Name
			if hasPrefix(method, forbiddenPrefixes) {
				t.Errorf("%s.%s: mutating method is not allowed in awsapi", name, method)
			}
			if !hasPrefix(method, allowedPrefixes) {
				t.Errorf("%s.%s: only Describe*/Get*/List* methods are allowed", name, method)
			}
		}
	}
}

// TestClientsFieldsAreCovered checks that every service client handed to the
// rules is one of the audited interfaces.
func TestClientsFieldsAreCovered(t *testing.T) {
	audited := map[reflect.Type]bool{}
	for _, typ := range allInterfaces {
		audited[typ] = true
	}
	clients := reflect.TypeFor[Clients]()
	for i := range clients.NumField() {
		field := clients.Field(i)
		if !audited[field.Type] {
			t.Errorf("Clients.%s has type %s, which is not in allInterfaces", field.Name, field.Type)
		}
	}
}

// TestAllInterfacesListed parses the package source so the reflection table
// above cannot silently fall behind the code.
func TestAllInterfacesListed(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var declared []string
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			for _, spec := range gen.Specs {
				ts := spec.(*ast.TypeSpec)
				if _, isIface := ts.Type.(*ast.InterfaceType); isIface {
					declared = append(declared, ts.Name.Name)
				}
			}
		}
	}
	if len(declared) == 0 {
		t.Fatal("found no interfaces; parser setup is broken")
	}
	sort.Strings(declared)
	for _, name := range declared {
		if _, ok := allInterfaces[name]; !ok {
			t.Errorf("interface %s is declared in awsapi but missing from allInterfaces", name)
		}
	}
	if len(declared) != len(allInterfaces) {
		t.Errorf("declared %d interfaces, allInterfaces lists %d", len(declared), len(allInterfaces))
	}
}

func hasPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
