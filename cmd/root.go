package cmd

import (
	"github.com/spf13/cobra"
)

var Root = &cobra.Command{
	Use:   "dedu",
	Short: "A tool to hash and deduplicate files",
}
