package cmd

import (
	"fmt"
	"time"

	awsclient "github.com/minhhieu21193/cloudaudit/internal/aws"
	"github.com/minhhieu21193/cloudaudit/internal/awsapi"
	"github.com/minhhieu21193/cloudaudit/internal/checks"
	"github.com/minhhieu21193/cloudaudit/internal/rules"
	"github.com/spf13/cobra"
)

var profile string

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan AWS account for cost waste",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		fmt.Fprintf(cmd.ErrOrStderr(), "Scanning AWS account with profile %q...\n", profile)
		client, err := awsclient.NewClient(profile)
		if err != nil {
			return fmt.Errorf("init AWS client for profile %q: %w", profile, err)
		}
		env := &checks.Env{
			Now:     time.Now(),
			Config:  checks.DefaultConfig(),
			Clients: awsapi.Clients{EC2: client.Ec2},
		}
		results, err := rules.EBSUnattached{}.Run(cmd.Context(), env)
		if err != nil {
			return fmt.Errorf("orphaned EBS check: %w", err)
		}
		for _, result := range results {
			fmt.Fprintln(cmd.OutOrStdout(), result)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVar(&profile, "profile", "default", "AWS profile to use")
}
