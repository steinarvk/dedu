package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/steinarvk/orc"

	orcdedu "github.com/steinarvk/dedu/module/orc-dedu"
)

var hashCmd = orc.Command(Root, orc.Modules(orcdedu.M), cobra.Command{
	Use:   "hash",
	Short: "Compute the dedu hash of files, or stdin",
}, func(filenames []string) error {
	dedu := orcdedu.M.Dedu

	show := func(deduhash, filename string) {
		fmt.Printf("%s\t%s\n", deduhash, filename)
	}

	if len(filenames) == 0 {
		deduhash, err := dedu.Hasher.ComputeHash(os.Stdin)
		if err != nil {
			return err
		}

		show(deduhash, "-")

		return nil
	}

	for _, filename := range filenames {
		if err := func() error {
			f, err := os.Open(filename)
			if err != nil {
				return err
			}
			defer f.Close()

			deduhash, err := dedu.Hasher.ComputeHash(f)
			if err != nil {
				return err
			}

			show(deduhash, filename)

			return nil
		}(); err != nil {
			return err
		}
	}

	return nil
})
