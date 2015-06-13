package command_authorize_import

import (
	"flag"
	"github.com/stbuehler/go-acme-client/requests"
	"github.com/stbuehler/go-acme-client/storage"
	"github.com/stbuehler/go-acme-client/types"
	"github.com/stbuehler/go-acme-client/ui"
	"github.com/stbuehler/go-acme-client/utils"
)

var register_flags = flag.NewFlagSet("register", flag.ExitOnError)

var storagePath string

func init() {
	storage.AddStorageFlags(register_flags)
	utils.AddLogFlags(register_flags)
}

func Run(UI ui.UserInterface, args []string) {
	register_flags.Parse(args)

	if 1 != len(register_flags.Args()) {
		utils.Fatalf("Missing url of authorization to import")
	}
	url := register_flags.Arg(0)

	_, reg := storage.OpenStorageFromFlags(UI)
	if nil == reg {
		utils.Fatalf("You need to register first")
	}

	auth, err := reg.LoadAuthorization(url)
	if nil != err {
		utils.Fatalf("Couldn't lookup authorization: %s", err)
	}
	if nil != auth {
		UI.Messagef("Already imported '%s'", url)
		return
	}

	importedAuth := types.Authorization{
		Location: url,
	}
	if err := requests.RefreshAuthorization(&importedAuth); nil != err {
		utils.Errorf("Couldn't retrieve authorization: %s", err)
	}

	UI.Messagef("Result: %#v", importedAuth)

	auth, err = reg.NewAuthorization(importedAuth)
	if nil != err {
		utils.Fatalf("Couldn't store the new authorization for %v: %s", url, err)
	}

	UI.Messagef("Imported authorization %v successfully", url)
}
