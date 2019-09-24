package cmd

import (
	"github.com/spf13/cobra"
	"github.com/steinarvk/orc"
)

var qCmd = orc.Command(Root, orc.Modules(), cobra.Command{
	Use:   "q",
	Short: "Commands to interact with a qmfs filesystem",
}, nil)
