package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/steinarvk/linetool/lib/lines"
	"github.com/steinarvk/orc"

	"github.com/steinarvk/dedu/lib/dedusecrets"
	orcdedu "github.com/steinarvk/dedu/module/orc-dedu"
	orcdeduq "github.com/steinarvk/dedu/module/orc-deduq"
)

func basenames(xs []string) []string {
	var rv []string
	for _, x := range xs {
		rv = append(rv, filepath.Base(x))
	}
	return rv
}

type registerOrGetOpts struct {
	dedu         *dedusecrets.Dedu
	readonly     bool
	alwaysVerify bool
	allowHashing bool
}

func (o registerOrGetOpts) registerOrGetEntity(filename string) (string, error) {
	deduq := orcdeduq.M
	if deduq.Root == "" {
		return "", fmt.Errorf("internal error: orcdeduq was not initialised")
	}

	info, err := os.Lstat(filename)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(filename)
		if err != nil {
			return "", err
		}
		logrus.Infof("Resolving symlink %q to %q", filename, target)
		filename = target
	}

	filename, err = filepath.Abs(filename)
	if err != nil {
		return "", fmt.Errorf("error getting absolute path of %q", filename)
	}

	qh, err := o.dedu.Quasihasher.QuasihashFile(filename)
	if err != nil {
		return "", err
	}

	entityPathsWithQH, err := deduq.Query(fmt.Sprintf("quasihash=%s", qh))
	if err != nil {
		return "", err
	}

	entitiesWithQH := basenames(entityPathsWithQH)

	var matchingEntities, unclearEntities []string

	for _, entity := range entitiesWithQH {
		entityPaths, err := deduq.FileLines(entity, "paths")
		if err != nil {
			return "", err
		}

		if lines.AsMap(entityPaths)[filename] {
			matchingEntities = append(matchingEntities, entity)
		} else {
			unclearEntities = append(unclearEntities, entity)
		}
	}

	if !o.alwaysVerify && len(matchingEntities) == 1 {
		entity := matchingEntities[0]

		return entity, nil
	}

	if !o.allowHashing {
		return "", fmt.Errorf("lookup for %q failed; would require hashing (%d result(s))", filename, len(entitiesWithQH))
	}

	dh, err := o.dedu.Hasher.ComputeFileHash(filename)
	if err != nil {
		return dh, err
	}

	if !o.readonly {
		// We found the answer; now register it.
		didFindRightEntity := false

		if err := lines.CreateOrExpect(deduq.Filename(dh, "quasihash"), []string{qh}); err != nil {
			return dh, err
		}

		for _, matchingEntity := range matchingEntities {
			if matchingEntity == dh {
				didFindRightEntity = false
				continue
			}

			// No longer matches.
			pathsFilePath := deduq.Filename(matchingEntity, "paths")
			if err := lines.RemoveFromFile(pathsFilePath, []string{filename}, true); err != nil {
				return dh, fmt.Errorf("error removing %q from %q: %v", filename, pathsFilePath, err)
			}
		}

		if !didFindRightEntity {
			pathsFilePath := deduq.Filename(dh, "paths")
			if err := lines.AddNewToFile(pathsFilePath, []string{filename}); err != nil {
				return dh, fmt.Errorf("error adding %q to %q: %v", filename, pathsFilePath, err)
			}
		}
	}

	return dh, nil
}

func init() {
	var flagReadonly bool
	var flagFullHash string
	var flagGetPath bool

	validFullHash := map[string]bool{
		"always": true,
		"never":  true,
		"auto":   true,
	}

	var qGetEntityCmd = orc.Command(qCmd, orc.Modules(orcdedu.M, orcdeduq.M), cobra.Command{
		Use:   "get-entity",
		Short: "Get entity ID corresponding to a file (registering it if not found)",
	}, func(filenames []string) error {
		if len(filenames) != 1 {
			return fmt.Errorf("got %d filename(s) (%v), expected exactly 1", len(filenames), filenames)
		}

		if !validFullHash[flagFullHash] {
			return fmt.Errorf("invalid value --full_hash=%q: allowed values are: always, never, auto", flagFullHash)
		}

		alwaysVerify := flagFullHash == "always"
		allowHashing := flagFullHash != "never"

		rogopts := registerOrGetOpts{
			readonly:     flagReadonly,
			alwaysVerify: alwaysVerify,
			allowHashing: allowHashing,
			dedu:         orcdedu.M.Dedu,
		}

		entityID, err := rogopts.registerOrGetEntity(filenames[0])
		if err != nil {
			return err
		}

		if flagGetPath {
			fmt.Println(orcdeduq.M.EntityPath(entityID))
		} else {
			fmt.Println(entityID)
		}

		return nil
	})

	qGetEntityCmd.Flags().BoolVar(&flagReadonly, "readonly", false, "read-only mode; don't register file if it can't be found")
	qGetEntityCmd.Flags().StringVar(&flagFullHash, "full_hash", "auto", "when to compute full hash (always, never, auto)")
	qGetEntityCmd.Flags().BoolVar(&flagGetPath, "path", false, "print full path of entity, not just ID")
}
