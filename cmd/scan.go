package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan AWS account for cost waste",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Scanning AWS account...")
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
