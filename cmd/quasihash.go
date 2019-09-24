package cmd

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/steinarvk/orc"

	"github.com/steinarvk/dedu/lib/quasihash"
	orcdedu "github.com/steinarvk/dedu/module/orc-dedu"
)

var quasihashCmd = orc.Command(Root, orc.Modules(orcdedu.M), cobra.Command{
	Use:   "quasihash",
	Short: "Compute a fast but collision-prone quasi-hash of files",
}, func(filenames []string) error {
	dedu := orcdedu.M.Dedu

	show := func(deduhash, filename string) {
		fmt.Printf("%s\t%s\n", deduhash, filename)
	}

	if len(filenames) == 0 {
		return fmt.Errorf("no filenames provided")
	}

	for _, filename := range filenames {
		deduquasihash, err := dedu.Quasihasher.QuasihashFile(filename)
		if err == quasihash.ErrIsDir {
			logrus.Warningf("warning: skipping directory %q\n", filename)
			continue
		}
		if err != nil {
			return err
		}

		show(deduquasihash, filename)
	}

	return nil
})
