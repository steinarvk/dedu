package orcdedu

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/steinarvk/dedu/lib/dedusecrets"
	"github.com/steinarvk/orc"

	orcconfigdir "github.com/steinarvk/orclib/module/orc-configdir"
)

var (
	SecretsConfigName = "deducfg.secret.pb_text"
	ConfigName        = "deducfg.pb_text"
)

type Module struct {
	Dedu *dedusecrets.Dedu
}

func (m *Module) ModuleName() string { return "Dedu" }

var M = &Module{}

func (m *Module) OnRegister(hooks orc.ModuleHooks) {
	var flagSecretsFilename string
	var flagConfigFilename string

	var flagVerbose bool

	hooks.OnUse(func(ctx orc.UseContext) {
		ctx.Use(orcconfigdir.M)

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
			flagSecretsFilename, _ = orcconfigdir.M.GetConfigPath(SecretsConfigName)
			flagConfigFilename, _ = orcconfigdir.M.GetConfigPath(ConfigName)

			hasAnyConfig := flagSecretsFilename != "" || flagConfigFilename != ""

			if !hasAnyConfig {
				return fmt.Errorf("expected %q or %q to exist in config dir", SecretsConfigName, ConfigName)
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
