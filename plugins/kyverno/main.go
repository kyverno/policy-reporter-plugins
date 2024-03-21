package main

import (
	"fmt"
	"os"

	"github.com/kyverno/policy-reporter/kyverno-plugin/cmd"
)

var Version = "development"

func main() {
	if err := cmd.NewCLI().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
