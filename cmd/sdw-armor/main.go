// Command sdw-armor audits and hardens the effective configuration of Linux
// hosts. See https://github.com/Shadow-Security-official/Shadow-Armor.
package main

import (
	"os"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr))
}
