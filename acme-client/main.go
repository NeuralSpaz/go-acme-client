package main

import (
	"github.com/stbuehler/go-acme-client/command_authorize"
	"github.com/stbuehler/go-acme-client/command_authorize_import"
	//	"github.com/stbuehler/go-acme-client/command_certificate"
	//	"github.com/stbuehler/go-acme-client/command_certificate_show"
	"github.com/stbuehler/go-acme-client/command_register"
	"github.com/stbuehler/go-acme-client/ui"
	"os"
)

func main() {
	ui.InitCLI()

	if len(os.Args) <= 1 {
		println("Existing sub commands: ")
		println("\tregister")
		println("\tauthorize")
		println("\tauthorize-import")
		println("\tcertificate")
		println("\tcertificate-show")
		os.Exit(1)
	} else {
		switch os.Args[1] {
		case "register":
			command_register.Run(ui.CLI, os.Args[2:])
		case "authorize":
			command_authorize.Run(ui.CLI, os.Args[2:])
		case "authorize-import":
			command_authorize_import.Run(ui.CLI, os.Args[2:])
			//		case "certificate":
			//			command_certificate.Run(ui.CLI, os.Args[2:])
			//		case "certificate-show":
			//			command_certificate_show.Run(ui.CLI, os.Args[2:])
		default:
			println("Unknown subcommand: " + os.Args[1])
			os.Exit(1)
		}
	}

}
