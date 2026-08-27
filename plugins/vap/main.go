package main

import (
	"fmt"
	"os"

	"github.com/kyverno/policy-reporter/vap-plugin/cmd"
)

// version is set via -ldflags at build time (see Makefile).
var version = "dev"

func main() {
	if err := cmd.NewCLI(version).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
