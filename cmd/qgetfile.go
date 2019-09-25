package cmd

import (
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/steinarvk/linetool/lib/lines"
	"github.com/steinarvk/orc"

	"github.com/steinarvk/dedu/lib/deduhash"

	orcdedu "github.com/steinarvk/dedu/module/orc-dedu"
	orcdeduq "github.com/steinarvk/dedu/module/orc-deduq"
)

func init() {
	var flagVerify bool
	var flagDiscoverSymlinks bool

	var qGetFileCmd = orc.Command(qCmd, orc.Modules(orcdedu.M, orcdeduq.M), cobra.Command{
		Use:   "get-file [ID]",
		Short: "Get path corresponding to entity ID",
	}, func(entityIDs []string) error {
		if len(entityIDs) == 0 {
			return fmt.Errorf("no entity IDs provided")
		}

		show := func(s string) {
			fmt.Println(s)
		}

		getOneFile := func(entityID string) error {
			deduq := orcdeduq.M
			dedu := orcdedu.M.Dedu

			qhs, err := deduq.FileLines(entityID, "quasihash")
			if err != nil {
				return err
			}

			if len(qhs) != 1 {
				return fmt.Errorf("expected exactly 1 quasihash for %q, got %v", entityID, qhs)
			}

			quasihash := qhs[0]

			paths, err := deduq.FileLines(entityID, "paths")
			if err != nil {
				return err
			}

			tryPath := func(path string) (bool, error) {
				info, err := os.Stat(path)
				if os.IsNotExist(err) {
					return false, nil
				}

				ok, err := dedu.Quasihasher.QuasihashVerifyFile(path, quasihash)
				if err != nil {
					return false, err
				}
				if !ok {
					return false, nil
				}

				if flagVerify {
					f, err := os.Open(path)
					if err != nil {
						return false, err
					}
					defer f.Close()

					ok, err := dedu.Hasher.VerifyHash(f, info.Size(), entityID)
					if err != nil {
						return false, err
					}
					if !ok {
						return false, err
					}
				}

				return true, nil
			}

			listed := lines.AsMap(paths)

			for _, path := range paths {
				info, err := os.Lstat(path)
				if os.IsNotExist(err) {
					continue
				}

				isSymlink := (info.Mode() & os.ModeSymlink) != 0
				if isSymlink {
					if !flagDiscoverSymlinks {
						continue
					}

					target, err := os.Readlink(path)
					if err != nil {
						continue
					}
					target, err = filepath.Abs(target)
					if err != nil {
						continue
					}
					if listed[target] {
						continue
					}

					ok, err := tryPath(target)
					if err != nil {
						continue
					}
					if ok {
						show(target)
						return nil
					}
				} else {
					ok, err := tryPath(path)
					if err != nil {
						continue
					}
					if ok {
						show(path)
						return nil
					}
				}
			}

			return fmt.Errorf("no suitable path found for %q (tried %v)", entityID, paths)
		}

		for _, entityID := range entityIDs {
			if !deduhash.LooksLikeDeduhash(entityID) {
				base := path.Base(entityID)
				if deduhash.LooksLikeDeduhash(base) {
					entityID = base
				} else {
					return fmt.Errorf("argument %q does not appear to be a hash", entityID)
				}
			}

			if err := getOneFile(entityID); err != nil {
				return err
			}
		}

		return nil
	})

	qGetFileCmd.Flags().BoolVar(&flagVerify, "verify", false, "verify every file by re-hashing")
	qGetFileCmd.Flags().BoolVar(&flagDiscoverSymlinks, "discover_symlinks", true, "follow symlinks and register targets if they match")
}
