package command_register

import (
	"flag"
	"fmt"
	"github.com/stbuehler/go-acme-client/requests"
	"github.com/stbuehler/go-acme-client/storage"
	"github.com/stbuehler/go-acme-client/ui"
	"github.com/stbuehler/go-acme-client/utils"
	"io/ioutil"
	"net/http"
	"reflect"
)

var register_flags = flag.NewFlagSet("register", flag.ExitOnError)

var rsabits int = 2048
var curve utils.Curve = utils.CurveP521
var keyType utils.KeyType = utils.KeyEcdsa
var storagePath string
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
	register_flags.StringVar(&storagePath, "storage", "storage.pem", "Storagefile")
	register_flags.StringVar(&registrationUrl, "url", demoRegistrationUrl, "Registration URL")
	register_flags.BoolVar(&no_update, "no-update", false, "Disable automatically fetching an updated registration")
	register_flags.BoolVar(&show_tos, "show-tos", false, "Show Terms of service if available, even when already agreed to something")
	register_flags.BoolVar(&agree_tos, "agree-tos", false, "Automatically agree to terms of service")
	register_flags.BoolVar(&modify, "modify", false, "Modify contact information")
	utils.AddLogFlags(register_flags)
}

func Run(UI ui.UserInterface, args []string) {
	register_flags.Parse(args)

	st, err := storage.LoadStorageFile(storagePath, UI.PasswordPromptOnce("Enter password: "))
	if nil != err {
		utils.Fatalf("Couldn't load the registration: %s", err)
	}

	if nil != st && !no_update {
		updatedReq, err := requests.FetchRegistration(st.RegistrationKey, st.RegistrationData)
		if nil != err {
			utils.Errorf("Couldn't update the registration: %s", err)
		} else {
			st.RegistrationData = updatedReq
			if err = storage.SaveStorageFile(storagePath, st); nil != err {
				utils.Errorf("Couldn't save the (updated) registration: %s", err)
			}
		}
	}

	if nil == st {
		fmt.Println("Creating new registration")
		pkey, err := utils.CreateSigningKey(keyType, curve, &rsabits)
		if nil != err {
			utils.Fatalf("Couldn't create private key for registration: %s", err)
		}
		contact, err := EnterNewContact(UI)
		if nil != err {
			utils.Fatalf("Couldn't get contact information for registration: %s", err)
		}
		newReq, err := requests.NewRegistration(registrationUrl, pkey, contact)
		if nil != err {
			utils.Fatalf("Registration failed: %s", err)
		}
		password, err := UI.NewPasswordPrompt("Enter new password for storage file", "Enter password again")
		if nil != err {
			utils.Errorf("Couldn't read new password for storage file: %s", err)
			utils.Warningf("Storing without password (as registration already succeeded)!!!")
		}
		st = &storage.Storage{
			StoragePassword:  password,
			RegistrationData: newReq,
			RegistrationKey:  pkey,
		}
		if err = storage.SaveStorageFile(storagePath, st); nil != err {
			utils.Errorf("Couldn't save the registration: %s", err)
		}
	} else {
		fmt.Println("Using existing registration")
	}

	modifiedRegistration := false

	if modify {
		newContact, err := EnterNewContact(UI)
		if nil != err {
			utils.Fatalf("Couldn't get new contact information: %s", err)
		}
		if !reflect.DeepEqual(newContact, st.RegistrationData.Contact) {
			st.RegistrationData.Contact = newContact
			modifiedRegistration = true
		}
	}

	if 0 != len(st.RegistrationData.UrlTermsOfService) && (show_tos || 0 == len(st.RegistrationData.Agreement)) {
		resp, err := http.Get(st.RegistrationData.UrlTermsOfService)
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
		if st.RegistrationData.Agreement == st.RegistrationData.UrlTermsOfService {
			fmt.Printf("The following terms of service are marked as already agreed to:\n%s\n", tos)
		} else if agree_tos {
			fmt.Printf("Automatically accepting the following terms of service as requested:\n%s\n", tos)
		} else {
			var title string
			if 0 == len(st.RegistrationData.Agreement) {
				title = "The server asks for confirmation of the following terms of service:"
			} else {
				title = "There are new terms of service:"
			}
			ack, err := UI.YesNoDialog(title, tos, "Agree?", false)
			if err != nil {
				utils.Fatalf("Couldn't read acknowledge for terms of service: %s", err)
			}
			if ack {
				if st.RegistrationData.Agreement != st.RegistrationData.UrlTermsOfService {
					// we might have shown it although the user already agreed to it
					st.RegistrationData.Agreement = st.RegistrationData.UrlTermsOfService
					modifiedRegistration = true
				}
			} else if 0 == len(st.RegistrationData.Agreement) {
				utils.Infof("Terms of service not accepted")
			} else {
				utils.Infof("New terms of service not accepted")
			}
		}
	}

	if modifiedRegistration {
		updatedReq, err := requests.UpdateRegistration(st.RegistrationKey, st.RegistrationData)
		if err != nil {
			utils.Fatalf("Couldn't update registration: %s", err)
		}
		st.RegistrationData = updatedReq
		if err = storage.SaveStorageFile(storagePath, st); nil != err {
			utils.Errorf("Couldn't save the (updated) registration: %s", err)
		}
	}

	fmt.Printf("Your registration URL is %s\n", st.RegistrationData.UrlSelf)
	fmt.Printf("Your registered contact information is: %v\n", st.RegistrationData.Contact)
	if 0 != len(st.RegistrationData.Agreement) {
		fmt.Printf("You agreed to the terms of service at %s\n", st.RegistrationData.Agreement)
	} else {
		fmt.Printf("You didn't agree to the terms of service at %s\n", st.RegistrationData.UrlTermsOfService)
	}
	fmt.Printf("The URL to request new authorizations is %s\n", st.RegistrationData.UrlAuth)
	fmt.Printf("Your recovery token is: %s\n", st.RegistrationData.RecoveryToken)
}
