package storage_sql

import (
	"flag"
	i "github.com/stbuehler/go-acme-client/storage_interface"
	"github.com/stbuehler/go-acme-client/ui"
	"github.com/stbuehler/go-acme-client/utils"
)

var flagsStoragePath string
var FlagsStorageAccount string

func AddStorageFlags(flags *flag.FlagSet) {
	flags.StringVar(&flagsStoragePath, "storage", "storage.sqlite3", "Storagefile")
	flags.StringVar(&FlagsStorageAccount, "account", "", "Account name in storage")
}

func OpenStorageFromFlags(UI ui.UserInterface) (i.Storage, i.StorageRegistration) {
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
