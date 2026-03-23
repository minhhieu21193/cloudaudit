package cmd

import (
	"context"
	"fmt"

	awsclient "github.com/minhhieu21193/cloudaudit/internal/aws"
	EBSOrphan "github.com/minhhieu21193/cloudaudit/internal/checks/aws/ebs"
	"github.com/spf13/cobra"
)

var profile string

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan AWS account for cost waste",
	Args:  cobra.ArbitraryArgs,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Scanning AWS account...")
		fmt.Printf("Your profile %s", profile)
		initClient, err := awsclient.NewClient(profile)
		if err != nil {
			fmt.Printf("An error occur when init new client with profile %s, please check your aws profile and make sure your profile valid", profile)
		}
		ctx := context.Background()
		checker := EBSOrphan.CheckOrphanedEBS{}
		resultsCheck, err := checker.Run(ctx, initClient)
		if err != nil {
			fmt.Printf("An error occur when check orphan EBS %s", &resultsCheck)
		}
		for _, result := range resultsCheck {
			fmt.Println(result)
		}

	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVar(&profile, "profile", "default", "AWS profile to use")
}
