package orcdeduq

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	orcdedu "github.com/steinarvk/dedu/module/orc-dedu"
	"github.com/steinarvk/linetool/lib/lines"
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
	Root string
}

func (m *Module) ModuleName() string { return "Dedu" }

var M = &Module{}

func (m *Module) Query(querystring string) ([]string, error) {
	if strings.Contains(querystring, "/") {
		return nil, fmt.Errorf("invalid query %q: contains /", querystring)
	}
	if strings.HasPrefix(querystring, ".") {
		return nil, fmt.Errorf("invalid query %q: begins with .", querystring)
	}

	return lines.ReadFile(m.Path(fmt.Sprintf("query/%s/list", querystring)))
}

func (m *Module) FileLines(entityID, filename string) ([]string, error) {
	return lines.ReadFile(m.Filename(entityID, filename))
}

func (m *Module) EntityPath(entityID string) string {
	return m.Path(fmt.Sprintf("entities/link/%s", entityID))
}

func (m *Module) Filename(entityID, filename string) string {
	return m.Path(fmt.Sprintf("entities/link/%s/%s", entityID, filename))
}

func (m *Module) Path(suffix string) string {
	return filepath.Join(m.Root, suffix)
}

func (m *Module) OnRegister(hooks orc.ModuleHooks) {
	var flagRootQMFS string

	hooks.OnUse(func(ctx orc.UseContext) {
		ctx.Use(orcdedu.M)

		ctx.Flags.StringVar(&flagRootQMFS, "qmfs", "", "qmfs root directory")
	})
	hooks.OnSetup(func() error {
		if flagRootQMFS == "" {
			flagRootQMFS = orcdedu.M.Dedu.Config.GetQmfs().GetQmfsRoot()
		}

		if flagRootQMFS == "" {
			return fmt.Errorf("no qmfs root provided")
		}

		pidfile := filepath.Join(flagRootQMFS, "service/pid")

		_, err := ioutil.ReadFile(pidfile)
		if os.IsNotExist(err) {
			return fmt.Errorf("invalid qmfs root (%q) provided: %q does not exist", flagRootQMFS, pidfile)
		}
		if err != nil {
			return fmt.Errorf("invalid qmfs root (%q) provided: error reading %q: %v", flagRootQMFS, pidfile, err)
		}

		m.Root = flagRootQMFS

		return nil
	})
}
