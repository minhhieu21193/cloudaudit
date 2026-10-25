package awsapi

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The read-only interfaces only help if code cannot get at a full SDK client
// some other way. Outside the two packages below, no production code may
// build an SDK client, recover one with a type assertion, or declare an
// interface with a mutating method (which would allow
// x.(interface{ DeleteVolume(...) }) on an awsapi value).
var sdkClientPackages = []string{"internal/awsclient", "internal/awsapi"}

var sdkServiceImport = regexp.MustCompile(`^github\.com/aws/aws-sdk-go-v2/service/[^/]+$`)

// sdkConstructors are the functions in every SDK service package that build
// a client.
var sdkConstructors = []string{"NewFromConfig", "New"}

func TestNoSDKClientsOutsideAWSClient(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	scanned := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			name := d.Name()
			if rel != "." && (strings.HasPrefix(name, ".") || slices.Contains([]string{"bin", "dist", "vendor", "testdata", "node_modules"}, name) || slices.Contains(sdkClientPackages, rel)) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		scanned++
		for _, v := range sdkViolations(t, fset, rel, string(src)) {
			t.Error(v)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Guard against a broken walk passing vacuously.
	if scanned < 30 {
		t.Fatalf("scanned only %d files under %s; the walk is broken", scanned, root)
	}
}

func TestSDKViolationsDetectsLoopholes(t *testing.T) {
	const header = `package x
import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	svc "github.com/aws/aws-sdk-go-v2/service/s3"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
)
`
	tests := []struct {
		name string
		body string
		want string // substring of the single expected violation; "" = none
	}{
		{"NewFromConfig", `func f(cfg aws.Config) { _ = ec2.NewFromConfig(cfg) }`, "calls ec2.NewFromConfig"},
		{"aliased New", `func f() { _ = svc.New(svc.Options{}) }`, "calls svc.New"},
		{"type assertion", `func f(c awsapi.Clients) { _ = c.EC2.(*ec2.Client) }`, "type-asserts to *ec2.Client"},
		{"comma-ok assertion via alias", `func f(c awsapi.Clients) { _, _ = c.S3.(*svc.Client) }`, "type-asserts to *svc.Client"},
		{"type switch", `func f(c awsapi.Clients) { switch c.EC2.(type) { case *ec2.Client: } }`, "type-asserts to *ec2.Client"},
		{"mutating interface literal", `func f(c awsapi.Clients) { _ = c.EC2.(interface{ DeleteVolume() }) }`, "declares mutating method DeleteVolume"},
		{"mutating named interface", `type stopper interface{ StopInstances() }`, "declares mutating method StopInstances"},
		{"paginator is fine", `func f(c awsapi.Clients) { _ = ec2.NewDescribeVolumesPaginator(c.EC2, nil) }`, ""},
		{"types package is fine", `func f(v any) { _ = v.(*ec2types.Volume) }`, ""},
		{"read-only or unrelated interface is fine", `func f(b any) { _ = b.(interface{ Demo() bool }); _ = b.(interface{ DescribeVolumes() }) }`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sdkViolations(t, token.NewFileSet(), "fixture.go", header+tt.body)
			switch {
			case tt.want == "" && len(got) != 0:
				t.Errorf("unexpected violations: %v", got)
			case tt.want != "" && (len(got) != 1 || !strings.Contains(got[0], tt.want)):
				t.Errorf("violations = %v, want one containing %q", got, tt.want)
			}
		})
	}

	dot := `package x
import . "github.com/aws/aws-sdk-go-v2/service/ec2"
`
	if got := sdkViolations(t, token.NewFileSet(), "dot.go", dot); len(got) != 1 || !strings.Contains(got[0], "dot-imports") {
		t.Errorf("dot import: violations = %v", got)
	}
}

// sdkViolations parses one file and reports every forbidden SDK usage.
func sdkViolations(t *testing.T, fset *token.FileSet, name, src string) []string {
	t.Helper()
	file, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}

	sdkPkgs := map[string]bool{} // local import names of SDK service packages
	var out []string
	report := func(pos token.Pos, format string, args ...any) {
		out = append(out, fmt.Sprintf("%s: %s", fset.Position(pos), fmt.Sprintf(format, args...)))
	}
	for _, imp := range file.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if !sdkServiceImport.MatchString(p) {
			continue
		}
		local := path.Base(p)
		if imp.Name != nil {
			local = imp.Name.Name
		}
		switch local {
		case "_":
		case ".":
			report(imp.Pos(), "dot-imports %s; import SDK service packages by name", p)
		default:
			sdkPkgs[local] = true
		}
	}

	// sdkSelector returns "pkg.Name" when e is Name selected from an SDK
	// service package.
	sdkSelector := func(e ast.Expr) (string, string, bool) {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok {
			return "", "", false
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || !sdkPkgs[pkg.Name] {
			return "", "", false
		}
		return pkg.Name, sel.Sel.Name, true
	}
	checkAssertedType := func(e ast.Expr) {
		if star, ok := e.(*ast.StarExpr); ok {
			if pkg, name, ok := sdkSelector(star.X); ok && name == "Client" {
				report(e.Pos(), "type-asserts to *%s.Client; use the awsapi interfaces", pkg)
			}
		}
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			if pkg, fn, ok := sdkSelector(n.Fun); ok && slices.Contains(sdkConstructors, fn) {
				report(n.Pos(), "calls %s.%s; only internal/awsclient may build SDK clients", pkg, fn)
			}
		case *ast.TypeAssertExpr:
			if n.Type != nil { // nil in a type switch; cases are checked below
				checkAssertedType(n.Type)
			}
		case *ast.TypeSwitchStmt:
			for _, stmt := range n.Body.List {
				for _, e := range stmt.(*ast.CaseClause).List {
					checkAssertedType(e)
				}
			}
		case *ast.InterfaceType:
			for _, m := range n.Methods.List {
				for _, id := range m.Names {
					if hasPrefix(id.Name, forbiddenPrefixes) {
						report(id.Pos(), "declares mutating method %s in an interface", id.Name)
					}
				}
			}
		}
		return true
	})
	return out
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
