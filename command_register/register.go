package command_register

import (
	"flag"
	"github.com/stbuehler/go-acme-client/requests"
	"github.com/stbuehler/go-acme-client/storage"
	"github.com/stbuehler/go-acme-client/types"
	"github.com/stbuehler/go-acme-client/ui"
	"github.com/stbuehler/go-acme-client/utils"
	"io/ioutil"
	"net/http"
	"reflect"
)

var register_flags = flag.NewFlagSet("register", flag.ExitOnError)

var rsabits int = 2048
var curve utils.Curve = utils.CurveP521
var keyType utils.KeyType = utils.KeyRSA
var storagePath string
var account string
var no_update bool
var show_tos bool
var agree_tos bool
var modify bool
var registrationUrl string

const demoRegistrationUrl = "https://www.letsencrypt-demo.org/acme/new-reg"

func init() {
	register_flags.IntVar(&rsabits, "rsa-bits", 2048, "Number of bits to generate the RSA key with (if selected)")
	register_flags.Var(&curve, "curve", "Elliptic curve to generate ECDSA key with (if selected), one of P-256, P-384, P-521")
	register_flags.Var(&keyType, "key-type", "Key type to generate, RSA or ECDSA")
	register_flags.StringVar(&registrationUrl, "url", demoRegistrationUrl, "Registration URL")
	register_flags.BoolVar(&no_update, "no-update", false, "Disable automatically fetching an updated registration")
	register_flags.BoolVar(&show_tos, "show-tos", false, "Show Terms of service if available, even when already agreed to something")
	register_flags.BoolVar(&agree_tos, "agree-tos", false, "Automatically agree to terms of service")
	register_flags.BoolVar(&modify, "modify", false, "Modify contact information")
	storage.AddStorageFlags(register_flags)
	utils.AddLogFlags(register_flags)
}

func Run(UI ui.UserInterface, args []string) {
	register_flags.Parse(args)

	st, reg := storage.OpenStorageFromFlags(UI)

	modifiedRegistration := false

	if nil != reg {
		if 0 == len(reg.Registration.Location) {
			UI.Message("Resubmitting registration")

			newReg, err := requests.NewRegistration(registrationUrl, reg.SigningKey, reg.Registration.Contact)
			if nil != err {
				utils.Fatalf("Registration failed: %s", err)
			}
			reg.Registration = *newReg
			if err := reg.Save(); nil != err {
				utils.Fatalf("Couldn't save the (updated) registration: %s", err)
			}
		} else if !no_update {
			UI.Message("Using existing registration")

			updatedReg, err := requests.FetchRegistration(reg.SigningKey, &reg.Registration)
			if nil != err {
				utils.Errorf("Couldn't update the registration: %s", err)
			} else {
				reg.Registration = *updatedReg
				if err := reg.Save(); nil != err {
					utils.Fatalf("Couldn't save the (updated) registration: %s", err)
				}
			}
		}

		if modify {
			newContact, err := EnterNewContact(UI)
			if nil != err {
				utils.Fatalf("Couldn't get new contact information: %s", err)
			}
			if !reflect.DeepEqual(newContact, reg.Registration.Contact) {
				reg.Registration.Contact = newContact
				modifiedRegistration = true
			}
		}
	} else {
		UI.Message("Creating new registration")

		signingKey, err := types.CreateSigningKey(keyType, curve, &rsabits)
		if nil != err {
			utils.Fatalf("Couldn't create private key for registration: %s", err)
		}
		contact, err := EnterNewContact(UI)
		if nil != err {
			utils.Fatalf("Couldn't get contact information for registration: %s", err)
		}

		password, err := UI.NewPasswordPrompt("Enter new password for account", "Enter password again")
		if nil != err {
			utils.Fatalf("Couldn't read new password for storage file: %s", err)
		}
		st.SetPassword(password)

		reg, err = st.NewRegistration(account, signingKey, types.Registration{
			Contact: contact,
		})
		if nil != err {
			utils.Fatalf("Couldn't create new registration in storage: %s", err)
		}

		newReg, err := requests.NewRegistration(registrationUrl, reg.SigningKey, reg.Registration.Contact)
		if nil != err {
			utils.Fatalf("Registration failed: %s", err)
		}
		reg.Registration = *newReg
		if err := reg.Save(); nil != err {
			utils.Fatalf("Couldn't save the (updated) registration: %s", err)
		}
	}

	if 0 != len(reg.Registration.LinkTermsOfService) && (show_tos || 0 == len(reg.Registration.Agreement)) {
		resp, err := http.Get(reg.Registration.LinkTermsOfService)
		if err != nil {
			utils.Fatalf("Couldn't retrieve terms of service: %s", err)
		}
		defer resp.Body.Close()
		if 200 != resp.StatusCode {
			utils.Fatalf("Couldn't retrieve terms of service: HTTP %s", resp.Status)
		}
		tosBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			utils.Fatalf("Couldn't read terms of service: %s", err)
		}
		tos := string(tosBytes)
		if reg.Registration.Agreement == reg.Registration.LinkTermsOfService {
			UI.Messagef("The following terms of service are marked as already agreed to:\n%s", tos)
		} else if agree_tos {
			UI.Messagef("Automatically accepting the following terms of service as requested:\n%s", tos)
		} else {
			var title string
			if 0 == len(reg.Registration.Agreement) {
				title = "The server asks for confirmation of the following terms of service:"
			} else {
				title = "There are new terms of service:"
			}
			ack, err := UI.YesNoDialog(title, tos, "Agree?", false)
			if err != nil {
				utils.Fatalf("Couldn't read acknowledge for terms of service: %s", err)
			}
			if ack {
				if reg.Registration.Agreement != reg.Registration.LinkTermsOfService {
					// we might have shown it although the user already agreed to it
					reg.Registration.Agreement = reg.Registration.LinkTermsOfService
					modifiedRegistration = true
				}
			} else if 0 == len(reg.Registration.Agreement) {
				utils.Infof("Terms of service not accepted")
			} else {
				utils.Infof("New terms of service not accepted")
			}
		}
	}

	if modifiedRegistration {
		updatedReq, err := requests.UpdateRegistration(reg.SigningKey, &reg.Registration)
		if err != nil {
			utils.Fatalf("Couldn't update registration: %s", err)
		}
		reg.Registration = *updatedReq
		if err := reg.Save(); nil != err {
			utils.Errorf("Couldn't save the (updated) registration: %s", err)
		}
	}

	UI.Messagef("Your registration URL is %s", reg.Registration.Location)
	UI.Messagef("Your registered contact information is: %v", reg.Registration.Contact)
	if 0 != len(reg.Registration.Agreement) {
		UI.Messagef("You agreed to the terms of service at %s", reg.Registration.Agreement)
	} else {
		UI.Messagef("You didn't agree to the terms of service at %s", reg.Registration.LinkTermsOfService)
	}
	UI.Messagef("The URL to request new authorizations is %s", reg.Registration.LinkAuth)
	UI.Messagef("Your recovery token is: %s", reg.Registration.RecoveryToken)
}
