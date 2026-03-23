package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "cloudaudit",
	Short: "Find wasted AWS spend from your terminal",
	Long:  "cloudaudit scans your AWS account for cost waste and outputs exact commands to fix it.",
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
