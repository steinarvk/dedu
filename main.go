package main

import (
	"github.com/sirupsen/logrus"
	"github.com/steinarvk/orclib/lib/orcmain"

	"github.com/steinarvk/dedu/cmd"
)

func init() {
	orcmain.Init("dedu", cmd.Root)
}

func main() {
	logrus.SetLevel(logrus.ErrorLevel)
	orcmain.Main(cmd.Root)
}
