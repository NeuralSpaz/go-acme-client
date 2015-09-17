package command_register

import (
	"flag"
	"fmt"
	"github.com/stbuehler/go-acme-client/command_base"
	"github.com/stbuehler/go-acme-client/types"
	"github.com/stbuehler/go-acme-client/ui"
	"github.com/stbuehler/go-acme-client/utils"
	"reflect"
)

var register_flags = flag.NewFlagSet("register", flag.ExitOnError)

var rsabits int = 2048
var curve utils.Curve = utils.CurveP521
var keyType utils.KeyType = utils.KeyRSA
var storagePath string
var no_refresh bool
var show_tos bool
var agree_tos bool
var modify bool
var directoryURL string

const demoDirectoryURL = "https://acme-staging.api.letsencrypt.org/directory"

func init() {
	register_flags.IntVar(&rsabits, "rsa-bits", 2048, "Number of bits to generate the RSA key with (if selected)")
	register_flags.Var(&curve, "curve", "Elliptic curve to generate ECDSA key with (if selected), one of P-256, P-384, P-521")
	register_flags.Var(&keyType, "key-type", "Key type to generate, RSA or ECDSA")
	register_flags.StringVar(&directoryURL, "url", demoDirectoryURL, "ACME Directory URL")
	register_flags.BoolVar(&no_refresh, "no-refresh", false, "Disable automatically fetching an updated registration")
	register_flags.BoolVar(&show_tos, "show-tos", false, "Show Terms of service if available, even when already agreed to something")
	register_flags.BoolVar(&agree_tos, "agree-tos", false, "Automatically agree to terms of service")
	register_flags.BoolVar(&modify, "modify", false, "Modify contact information")
	command_base.AddStorageFlags(register_flags)
	utils.AddLogFlags(register_flags)
}

func Run(UI ui.UserInterface, args []string) {
	register_flags.Parse(args)

	st, controller, reg := command_base.OpenStorageFromFlags(UI)

	var newContact []string
	var newAgreementURL *string

	if nil != reg {
		if !no_refresh {
			UI.Message("Using existing registration")

			if err := reg.Refresh(); nil != err {
				utils.Errorf("Couldn't refresh the registration: %s", err)
			}
		}

		if modify {
			var err error
			if newContact, err = EnterNewContact(UI); nil != err {
				utils.Fatalf("Couldn't get new contact information: %s", err)
			}
			if reflect.DeepEqual(newContact, reg.Registration().Resource.Contact) {
				UI.Messagef("Entered contact information is the same we already have, ignoring update")
				newContact = nil // no changes
			}
		}
	} else {
		UI.Message("Creating new registration")

		dir, err := controller.GetDirectory(demoDirectoryURL, false)
		if nil != err {
			utils.Fatalf("Couldn't fetch directory for '%s': %s", demoDirectoryURL, err)
		}

		UI.Message("Generating private key, might take some time")
		signingKey, err := types.CreateSigningKey(keyType, curve, &rsabits)
		if nil != err {
			utils.Fatalf("Couldn't create private key for registration: %s", err)
		}
		contact, err := EnterNewContact(UI)
		if nil != err {
			utils.Fatalf("Couldn't get contact information for registration: %s", err)
		}

		if password, err := UI.NewPasswordPrompt("Enter new password for account", "Enter password again"); nil != err {
			utils.Fatalf("Couldn't read new password for storage file: %s", err)
		} else {
			st.SetPassword(password)
		}

		if reg, err = dir.NewRegistration(command_base.FlagsStorageRegistrationName, signingKey, contact); nil != err {
			utils.Fatalf("Couldn't create registration: %s", err)
		}
	}

	regData := reg.Registration()

	if 0 != len(regData.LinkTermsOfService) && (show_tos || 0 == len(regData.Resource.AgreementURL)) {
		if regData.Resource.AgreementURL == regData.LinkTermsOfService {
			UI.Messagef("The terms of service at %s are marked as already agreed to.", regData.LinkTermsOfService)
		} else if agree_tos {
			UI.Messagef("Automatically accepting the terms of service at %s as requested:", regData.LinkTermsOfService)
			newAgreementURL = &regData.LinkTermsOfService
		} else {
			var title string
			if 0 == len(regData.Resource.AgreementURL) {
				title = "The server asks for confirmation of the terms of service at %s"
			} else {
				title = "There are new terms of service at %s"
			}
			ack, err := UI.YesNoDialog(fmt.Sprintf(title, regData.LinkTermsOfService), "", "Agree?", false)
			if err != nil {
				utils.Fatalf("Couldn't read acknowledge for terms of service: %s", err)
			}
			if ack {
				newAgreementURL = &regData.LinkTermsOfService
			} else if 0 == len(regData.Resource.AgreementURL) {
				utils.Infof("Terms of service not accepted")
			} else {
				utils.Infof("New terms of service not accepted")
			}
		}
	}

	if err := reg.Update(newContact, newAgreementURL); err != nil {
		utils.Fatalf("Couldn't update registration: %s", err)
	}
	regData = reg.Registration()

	UI.Messagef("Your registration URL is %s", regData.Location)
	UI.Messagef("Your registered contact information is: %v", regData.Resource.Contact)
	if 0 != len(regData.Resource.AgreementURL) {
		UI.Messagef("You agreed to the terms of service at %s", regData.Resource.AgreementURL)
	} else {
		UI.Messagef("You didn't agree to the terms of service at %s", regData.LinkTermsOfService)
	}
	UI.Messagef("Your recovery token is: %s", regData.RecoveryToken)
}
