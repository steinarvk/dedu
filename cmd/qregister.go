package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/steinarvk/linetool/lib/lines"
	"github.com/steinarvk/orc"

	orcdedu "github.com/steinarvk/dedu/module/orc-dedu"
	orcdeduq "github.com/steinarvk/dedu/module/orc-deduq"
)

func toString(data interface{}) (string, bool) {
	switch val := data.(type) {
	case string:
		return strings.TrimSpace(val) + "\n", true

	case float32:
		return fmt.Sprintf("%f", val), true
	case float64:
		return fmt.Sprintf("%f", val), true

	case int:
		return fmt.Sprintf("%d", val), true
	case int64:
		return fmt.Sprintf("%d", val), true

	case []byte:
		return string(val), true

	case bool:
		if val {
			return "true\n", true
		}
		return "false\n", true

	default:
		return "", false
	}
}

func importMetadataFromFile(entityID, metafile string) error {
	deduq := orcdeduq.M
	if deduq.Root == "" {
		return fmt.Errorf("internal error: orcdeduq was not initialised")
	}

	data, err := ioutil.ReadFile(metafile)
	if err != nil {
		return fmt.Errorf("error reading %q: %v", metafile, err)
	}

	m := map[string]interface{}{}

	if err := yaml.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("error parsing %q: %v", metafile, err)
	}

	pattern := regexp.MustCompile(`^[a-z0-9-]+$`)

	for metaAttrib, value := range m {
		if !pattern.MatchString(metaAttrib) {
			return fmt.Errorf("unacceptable metadata attribute name: %q", metaAttrib)
		}

		metapath := deduq.Filename(entityID, metaAttrib)
		valueString, ok := toString(value)
		if !ok {
			return fmt.Errorf("Unable to convert value %q: %v to string; skipping.", metaAttrib, value)
		}

		_, err := os.Stat(metapath)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("error on Stat(%q): %v", metapath, err)
		}
		if err == nil {
			logrus.WithFields(logrus.Fields{
				"entity_id":     entityID,
				"metadata_file": metafile,
				"attrib_file":   metapath,
			}).Infof("File already exists; skipping.")
			continue
		}

		if err := ioutil.WriteFile(metapath, []byte(valueString), 0600); err != nil {
			return fmt.Errorf("error on WriteFile(%q): %v", metapath, err)
		}
	}

	return nil
}

func init() {
	var flagVerify bool
	var flagMetadataFromYAMLSuffixes []string

	var qRegisterCmd = orc.Command(qCmd, orc.Modules(orcdedu.M, orcdeduq.M), cobra.Command{
		Use:   "register [FILE...]",
		Short: "Register file(s) as entities",
	}, func(filenames []string) error {
		registerOne := func(filename string) (string, error) {
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
			return entityID, err
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

			entityID, err := registerOne(filename)
			if err != nil {
				return fmt.Errorf("error registering %q: %v", filename, err)
			}

			for _, suffix := range flagMetadataFromYAMLSuffixes {
				metafile := filename + suffix
				_, err := os.Stat(metafile)
				if os.IsNotExist(err) {
					continue
				}
				if err != nil {
					return fmt.Errorf("Stat(%q) returned error: %v", metafile, err)
				}

				if err := importMetadataFromFile(entityID, metafile); err != nil {
					return fmt.Errorf("error importing metadata from %q: %v", metafile, err)
				}
			}
		}

		return nil
	})

	qRegisterCmd.Flags().BoolVar(&flagVerify, "verify", false, "verify every file by re-hashing")
	qRegisterCmd.Flags().StringSliceVar(&flagMetadataFromYAMLSuffixes, "metadata_yaml_suffix", nil, "create qmfs metadata from adjacent YAML files")
}
