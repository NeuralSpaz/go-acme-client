package command_authorize_import

import (
	"flag"
	"fmt"
	"github.com/stbuehler/go-acme-client/requests"
	"github.com/stbuehler/go-acme-client/storage"
	"github.com/stbuehler/go-acme-client/ui"
	"github.com/stbuehler/go-acme-client/utils"
)

var register_flags = flag.NewFlagSet("register", flag.ExitOnError)

var storagePath string

func init() {
	register_flags.StringVar(&storagePath, "storage", "storage.pem", "Storagefile")
	utils.AddLogFlags(register_flags)
}

func Run(UI ui.UserInterface, args []string) {
	register_flags.Parse(args)

	if 1 != len(register_flags.Args()) {
		utils.Fatalf("Missing url of authorization to import")
	}
	url := register_flags.Arg(0)

	st, err := storage.LoadStorageFile(storagePath, UI.PasswordPromptOnce("Enter password: "))
	if nil != err {
		utils.Fatalf("Couldn't load the registration: %s", err)
	}

	if nil == st.RegistrationData {
		utils.Fatalf("You need to register first")
	}

	for _, auth := range st.Authorizations {
		if auth.UrlSelf == url {
			fmt.Printf("Already imported '%s'", url)
			return
		}
	}

	auth := requests.Authorization{
		UrlSelf: url,
	}
	if err = auth.Refresh(); nil != err {
		utils.Fatalf("Couldn't import authorization %s: %s", url, err)
	}

	if nil == auth.PublicKey {
		utils.Warningf("Couldn't verify ownership of authentication\n")
		auth.PublicKey = st.RegistrationKey.GetPublicKey()
	} else {
		if !utils.EqualJsonWebKey(*auth.PublicKey, *st.RegistrationKey.GetPublicKey()) {
			utils.Fatalf("Public key of registration doesn't match our own key")
		}
	}

	st.Authorizations = append(st.Authorizations, auth)
	if err = storage.SaveStorageFile(storagePath, st); nil != err {
		utils.Fatalf("Couldn't save the new authorization: %s", err)
	}

	UI.Message(fmt.Sprintf("Imported authorization %v successfully", url))

	utils.Debugf("Authorizations: %v\n", st.Authorizations)
}
