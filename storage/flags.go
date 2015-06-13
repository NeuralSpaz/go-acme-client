package storage

import (
	"flag"
	"github.com/stbuehler/go-acme-client/ui"
	"github.com/stbuehler/go-acme-client/utils"
)

var flagsStoragePath string
var FlagsStorageAccount string

func AddStorageFlags(flags *flag.FlagSet) {
	flags.StringVar(&flagsStoragePath, "storage", "storage.sqlite3", "Storagefile")
	flags.StringVar(&FlagsStorageAccount, "account", "", "Account name in storage")
}

func OpenStorageFromFlags(UI ui.UserInterface) (Storage, *StorageRegistration) {
	st, err := OpenSQLite(UI, flagsStoragePath)
	if nil != err {
		utils.Fatalf("Couldn't access storage: %s", err)
	}

	reg, err := st.LoadRegistration(FlagsStorageAccount)
	if nil != err {
		utils.Fatalf("Couldn't load the registration: %s", err)
	}
	// reg still can be nil!

	return st, reg
}
