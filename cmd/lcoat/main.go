// Command lcoat is the Lab Coat Lite control-plane CLI.
package main

import (
	"os"

	"github.com/rodriguezaa22ar-boop/go-project/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
