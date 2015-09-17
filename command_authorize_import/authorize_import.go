package command_authorize_import

import (
	"flag"
	"github.com/stbuehler/go-acme-client/command_base"
	"github.com/stbuehler/go-acme-client/ui"
	"github.com/stbuehler/go-acme-client/utils"
)

var register_flags = flag.NewFlagSet("register", flag.ExitOnError)

var storagePath string

func init() {
	command_base.AddStorageFlags(register_flags)
	utils.AddLogFlags(register_flags)
}

func Run(UI ui.UserInterface, args []string) {
	register_flags.Parse(args)

	if 1 != len(register_flags.Args()) {
		utils.Fatalf("Missing url of authorization to import")
	}
	url := register_flags.Arg(0)

	_, _, reg := command_base.OpenStorageFromFlags(UI)
	if nil == reg {
		utils.Fatalf("You need to register first")
	}

	auth, err := reg.GetAuthorizationByURL(url, true)
	if nil != err {
		utils.Fatalf("Couldn't retrieve authorization: %s", err)
	}

	UI.Messagef("Imported authorization %v successfully: %#v", url, auth.Authorization())
}
