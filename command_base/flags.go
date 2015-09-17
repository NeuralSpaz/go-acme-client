package command_base

import (
	"flag"
	"github.com/stbuehler/go-acme-client/model"
	"github.com/stbuehler/go-acme-client/storage_interface"
	"github.com/stbuehler/go-acme-client/storage_sql"
	"github.com/stbuehler/go-acme-client/ui"
	"github.com/stbuehler/go-acme-client/utils"
)

var flagsStoragePath string
var FlagsStorageRegistrationName string

func AddStorageFlags(flags *flag.FlagSet) {
	flags.StringVar(&flagsStoragePath, "storage", "storage.sqlite3", "Storagefile")
	flags.StringVar(&FlagsStorageRegistrationName, "registration", "", "Registration name in storage")
}

func OpenStorageFromFlags(UI ui.UserInterface) (storage_interface.Storage, model.Controller, model.RegistrationModel) {
	st, err := storage_sql.OpenSQLite(UI, flagsStoragePath)
	if nil != err {
		utils.Fatalf("Couldn't access storage: %s", err)
	}

	controller := model.MakeController(st)

	reg, err := controller.LoadRegistration(FlagsStorageRegistrationName)
	if nil != err {
		utils.Fatalf("Couldn't load the registration: %s", err)
	}
	// reg still can be nil!

	return st, controller, reg
}
