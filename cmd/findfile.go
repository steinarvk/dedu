package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	orcdedu "github.com/steinarvk/dedu/module/orc-dedu"
	"github.com/steinarvk/orc"
)

func getLinesFromReader(r io.Reader) ([]string, error) {
	var rv []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		text := scanner.Text()
		if strings.TrimSpace(text) == "" {
			continue
		}
		rv = append(rv, text)
	}
	return rv, nil
}

func getLinesFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	return getLinesFromReader(file)
}

func init() {
	var flagQuasihash string
	var flagHash string
	var flagPathsfile string

	var findFileCmd = orc.Command(Root, orc.Modules(orcdedu.M), cobra.Command{
		Use:   "findfile",
		Short: "Find a file from a list of paths by quasihash or dedu hash",
	}, func(filenames []string) error {
		dedu := orcdedu.M.Dedu

		if flagQuasihash == "" && flagHash == "" {
			return fmt.Errorf("must provide either --quasihash or --hash")
		}

		if flagPathsfile == "" {
			return fmt.Errorf("must provide --paths_file")
		}

		paths, err := getLinesFromFile(flagPathsfile)
		if err != nil {
			return err
		}

		if len(paths) == 0 {
			return fmt.Errorf("found no paths in %q", flagPathsfile)
		}

		listed := map[string]bool{}
		for _, path := range paths {
			listed[path] = true
		}

		tryPath := func(path string) (bool, error) {
			info, err := os.Stat(path)
			if os.IsNotExist(err) {
				return false, nil
			}

			if flagQuasihash != "" {
				ok, err := dedu.Quasihasher.QuasihashVerifyFile(path, flagQuasihash)
				if err != nil {
					return false, err
				}
				if !ok {
					return false, nil
				}
			}

			if flagHash != "" {
				f, err := os.Open(path)
				if err != nil {
					return false, err
				}
				defer f.Close()

				ok, err := dedu.Hasher.VerifyHash(f, info.Size(), flagHash)
				if err != nil {
					return false, err
				}
				if !ok {
					return false, err
				}
			}
			return true, nil
		}

		for _, path := range paths {
			info, err := os.Lstat(path)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				logrus.WithFields(logrus.Fields{"filename": path}).Warningf("Lstat error: %v", err)
				continue
			}

			isSymlink := (info.Mode() & os.ModeSymlink) != 0
			if isSymlink {
				target, err := os.Readlink(path)
				if err != nil {
					logrus.WithFields(logrus.Fields{"filename": path}).Warningf("Readlink error: %v", err)
					continue
				}
				target, err = filepath.Abs(target)
				if err != nil {
					logrus.WithFields(logrus.Fields{"filename": path}).Warningf("Abs error: %v", err)
					continue
				}

				if listed[target] {
					continue
				}

				ok, err := tryPath(target)
				if err != nil {
					logrus.WithFields(logrus.Fields{"filename": path, "link_target": target}).Warningf("Error: %v", err)
					continue
				}
				if ok {
					fmt.Println(path)
					return nil
				}
			}

			ok, err := tryPath(path)
			if err != nil {
				logrus.WithFields(logrus.Fields{"filename": path}).Warningf("Error: %v", err)
				continue
			}
			if ok {
				fmt.Println(path)
				return nil
			}
		}

		return fmt.Errorf("no valid path found")
	})

	findFileCmd.Flags().StringVar(&flagQuasihash, "quasihash", "", "quasihash of file to locate")
	findFileCmd.Flags().StringVar(&flagHash, "hash", "", "deduhash of file to locate (and verify)")
	findFileCmd.Flags().StringVar(&flagPathsfile, "paths_file", "", "file containing possible paths of file")
}
