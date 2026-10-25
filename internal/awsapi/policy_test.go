package awsapi

import (
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const (
	policyPath = "../../docs/iam-policy.json"
	cfnPath    = "../../deploy/cloudformation/audit-role.yaml"
)

// iamAction maps an SDK operation to the IAM action that authorizes it.
// The service prefix comes from the interface; a few S3 operations are
// authorized by differently named actions.
func iamAction(service, method string) string {
	switch service + "." + method {
	case "S3.ListBuckets":
		return "s3:ListAllMyBuckets"
	case "S3.GetPublicAccessBlock":
		return "s3:GetBucketPublicAccessBlock"
	case "S3Control.GetPublicAccessBlock":
		return "s3:GetAccountPublicAccessBlock"
	}
	prefix := map[string]string{
		"EC2": "ec2", "CloudWatch": "cloudwatch", "ELBv2": "elasticloadbalancing",
		"IAM": "iam", "RDS": "rds", "CloudTrail": "cloudtrail",
	}[service]
	return prefix + ":" + method
}

// requiredActions lists the IAM actions behind every operation the rules can
// reach. STS GetCallerIdentity needs no permission and is not included.
func requiredActions(t *testing.T) []string {
	t.Helper()
	var actions []string
	clients := reflect.TypeFor[Clients]()
	for i := range clients.NumField() {
		field := clients.Field(i)
		for m := range field.Type.NumMethod() {
			actions = append(actions, iamAction(field.Name, field.Type.Method(m).Name))
		}
	}
	slices.Sort(actions)
	return slices.Compact(actions)
}

func TestIAMPolicyMatchesCode(t *testing.T) {
	raw, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Statement []struct {
			Effect   string
			Action   []string
			Resource string
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s is not valid JSON: %v", policyPath, err)
	}
	if len(doc.Statement) != 1 || doc.Statement[0].Effect != "Allow" {
		t.Fatalf("want a single Allow statement, got %+v", doc.Statement)
	}
	assertSameActions(t, policyPath, doc.Statement[0].Action, requiredActions(t))
}

func TestCloudFormationInlinePolicyMatchesCode(t *testing.T) {
	raw, err := os.ReadFile(cfnPath)
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)# BEGIN cloudaudit-actions\n(.*?)# END cloudaudit-actions`).FindSubmatch(raw)
	if block == nil {
		t.Fatal("action markers not found in audit-role.yaml")
	}
	var actions []string
	for _, line := range strings.Split(string(block[1]), "\n") {
		if a := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- ")); a != "" {
			actions = append(actions, a)
		}
	}
	assertSameActions(t, cfnPath, actions, requiredActions(t))

	for _, want := range []string{"sts:ExternalId", "policy/SecurityAudit", "policy/job-function/ViewOnlyAccess"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("audit-role.yaml missing %q", want)
		}
	}
}

func assertSameActions(t *testing.T, file string, got, want []string) {
	t.Helper()
	for _, a := range got {
		if strings.Contains(a, "*") {
			t.Errorf("%s: wildcard action %q; list exact actions", file, a)
		}
		_, name, _ := strings.Cut(a, ":")
		if !hasPrefix(name, allowedPrefixes) {
			t.Errorf("%s: %q is not a read-only Describe/Get/List action", file, a)
		}
	}
	sorted := slices.Sorted(slices.Values(got))
	if !slices.Equal(sorted, want) {
		for _, a := range want {
			if !slices.Contains(sorted, a) {
				t.Errorf("%s is missing %s, which the code calls", file, a)
			}
		}
		for _, a := range sorted {
			if !slices.Contains(want, a) {
				t.Errorf("%s grants %s, which the code never calls", file, a)
			}
		}
	}
}
