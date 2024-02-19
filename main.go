package main

import (
	"embed"
	"github.com/sirupsen/logrus"
	"hlf-easy/cmd"

	"os"
)

//go:embed web/*
var views embed.FS

func main() {
	lvl, ok := os.LookupEnv("LOG_LEVEL")
	// LOG_LEVEL not set, let's default to debug
	if !ok {
		lvl = "info"
	}
	// parse string, this is built-in feature of logrus
	ll, err := logrus.ParseLevel(lvl)
	if err != nil {
		ll = logrus.DebugLevel
	}
	// set global log level
	logrus.SetLevel(ll)
	if err := cmd.NewCmdHLFEasy(views).Execute(); err != nil {
		os.Exit(1)
	}
}
