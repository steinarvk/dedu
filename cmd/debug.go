package cmd

import (
	"github.com/spf13/cobra"
	"github.com/steinarvk/orc"
)

var debugCmd = orc.Command(Root, orc.Modules(), cobra.Command{
	Use:   "debug",
	Short: "Debug/development commands",
}, nil)
