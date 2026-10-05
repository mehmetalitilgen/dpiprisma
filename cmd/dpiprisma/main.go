package main

import (
	"fmt"
	"os"

	"github.com/mehmetalitilgen/dpiprisma/internal/cli"
)

var version = "dev"

func main() {
	err := cli.Execute(version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
