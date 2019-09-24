package cmd

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/steinarvk/linetool/lib/lines"
	"github.com/steinarvk/orc"

	orcdedu "github.com/steinarvk/dedu/module/orc-dedu"
	orcdeduq "github.com/steinarvk/dedu/module/orc-deduq"
)

func init() {
	var flagVerify bool

	var qRegisterCmd = orc.Command(qCmd, orc.Modules(orcdedu.M, orcdeduq.M), cobra.Command{
		Use:   "register [FILE...]",
		Short: "Register file(s) as entities",
	}, func(filenames []string) error {
		registerOne := func(filename string) error {
			opts := registerOrGetOpts{
				dedu:         orcdedu.M.Dedu,
				readonly:     false,
				alwaysVerify: flagVerify,
				allowHashing: true,
			}
			entityID, err := opts.registerOrGetEntity(filename)
			if err == nil {
				fmt.Printf("%s\t%s\n", entityID, filename)
			}
			return err
		}

		// TODO could stream this
		if len(filenames) == 0 {
			logrus.Infof("Reading filenames from stdin")
			lines, err := lines.Read(os.Stdin)
			if err != nil {
				return fmt.Errorf("error reading filenames from stdin: %v", err)
			}
			filenames = lines
		}

		for _, filename := range filenames {
			_, err := os.Stat(filename)
			if os.IsNotExist(err) {
				return fmt.Errorf("file %q does not exist: %v", filename, err)
			}

			if err := registerOne(filename); err != nil {
				return fmt.Errorf("error registering %q: %v", filename, err)
			}
		}

		return nil
	})

	qRegisterCmd.Flags().BoolVar(&flagVerify, "verify", false, "verify every file by re-hashing")
}
