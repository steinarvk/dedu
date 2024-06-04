package orcdedu

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/sirupsen/logrus"
	"github.com/steinarvk/dedu/lib/dedusecrets"
	"github.com/steinarvk/orc"
)

var (
	ConfigDirs = []string{
		"~/.config/dedu",
		"~/.dedu",
		"/etc/dedu/",
	}

	SecretsConfigName = "deducfg.secret.pb_text"
	ConfigName        = "deducfg.pb_text"
)

type Module struct {
	Dedu *dedusecrets.Dedu
}

func pathIfFileExists(path string) (string, error) {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return path, nil
}

func findConfigDir() (string, bool, error) {
	for _, path := range ConfigDirs {
		if strings.HasPrefix(path, "~") {
			expanded, err := homedir.Expand(path)
			if err != nil {
				return "", false, fmt.Errorf("Failed to expand homedir in %q: %v", path, err)
				continue
			}
			path = expanded
		}

		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			continue
		}
		if !info.IsDir() {
			continue
		}
		return path, true, nil
	}
	return "", false, nil
}

func (m *Module) ModuleName() string { return "Dedu" }

var M = &Module{}

func (m *Module) OnRegister(hooks orc.ModuleHooks) {
	var flagSecretsFilename string
	var flagConfigFilename string

	var flagVerbose bool

	hooks.OnUse(func(ctx orc.UseContext) {
		ctx.Flags.StringVar(&flagSecretsFilename, "dedu_secret_config", "", "dedu secrets config (which may also include regular)")
		ctx.Flags.StringVar(&flagConfigFilename, "dedu_config", "", "dedu non-secret config")
		ctx.Flags.BoolVar(&flagVerbose, "verbose", false, "verbose log output")
	})
	hooks.OnSetup(func() error {
		logrus.SetLevel(logrus.ErrorLevel)
		if flagVerbose {
			logrus.SetLevel(logrus.DebugLevel)
		}

		hasExplicitConfig := flagSecretsFilename != "" || flagConfigFilename != ""
		if !hasExplicitConfig {
			cfgDir, ok, err := findConfigDir()
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("no config flag and no standard config dir exists (out of: %v)", ConfigDirs)
			}

			flagSecretsFilename, err = pathIfFileExists(filepath.Join(cfgDir, SecretsConfigName))
			if err != nil {
				return err
			}

			flagConfigFilename, err = pathIfFileExists(filepath.Join(cfgDir, ConfigName))
			if err != nil {
				return err
			}

			hasAnyConfig := flagSecretsFilename != "" || flagConfigFilename != ""
			if !hasAnyConfig {
				return fmt.Errorf("expected %q or %q to exist in config dir %q", SecretsConfigName, ConfigName, cfgDir)
			}
		}

		dedu, err := dedusecrets.LoadFromFile(flagSecretsFilename, flagConfigFilename)
		if err != nil {
			return err
		}

		emptyHash, err := dedu.Hasher.ComputeHash(strings.NewReader(""))
		if err != nil {
			return err
		}
		logrus.Infof("Hash of empty blob: %q", emptyHash)
		if h := dedu.Config.EmptyBlobHashSanityCheck; h != "" {
			if h != emptyHash {
				return fmt.Errorf("Config mismatch: expected %q to be hash of empty blob, but got %q", h, emptyHash)
			}
		}

		m.Dedu = dedu

		return nil
	})
}
