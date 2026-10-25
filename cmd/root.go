package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// version is set at build time with
// -ldflags "-X github.com/minhhieu21193/cloudaudit/cmd.version=v1.2.3".
var version = "dev"

// Exit codes, stable for CI use.
const (
	ExitOK       = 0
	ExitError    = 1
	ExitFindings = 2
)

// exitError carries a specific exit code out of a command.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func toolVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}

func newRootCmd(newBackend backendFactory) *cobra.Command {
	root := &cobra.Command{
		Use:   "cloudaudit",
		Short: "Read-only AWS cost and security audit",
		Long: `cloudaudit scans an AWS account with read-only API calls, finds wasted spend
and common security misconfigurations, and writes a report with the evidence
and a suggested fix command for each finding. It never modifies a resource.`,
		Version:       toolVersion(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newScanCmd(newBackend), newChecksCmd())
	return root
}

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return run(ctx, os.Args[1:], os.Stdout, os.Stderr, defaultBackend)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, newBackend backendFactory) int {
	root := newRootCmd(newBackend)
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return ExitOK
	}
	var ee *exitError
	if errors.As(err, &ee) {
		fmt.Fprintln(stderr, ee.msg)
		return ee.code
	}
	fmt.Fprintln(stderr, "Error:", err)
	return ExitError
}
