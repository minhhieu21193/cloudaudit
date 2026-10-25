package cmd

import (
	"fmt"
	"text/tabwriter"

	"github.com/minhhieu21193/cloudaudit/internal/rules"
	"github.com/spf13/cobra"
)

func newChecksCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "checks",
		Short: "List the available checks",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tCATEGORY\tSCOPE\tDESCRIPTION")
			for _, c := range rules.All() {
				m := c.Meta()
				scope := "region"
				if m.Global {
					scope = "account"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", m.ID, m.Category, scope, m.Name)
			}
			return w.Flush()
		},
	}
}
