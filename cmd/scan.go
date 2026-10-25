package cmd

import (
	"fmt"

	awsclient "github.com/minhhieu21193/cloudaudit/internal/aws"
	EBSOrphan "github.com/minhhieu21193/cloudaudit/internal/checks/aws/ebs"
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
		checker := EBSOrphan.CheckOrphanedEBS{}
		results, err := checker.Run(cmd.Context(), client)
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
