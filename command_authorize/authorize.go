package command_authorize

import (
	"flag"
	"fmt"
	"github.com/stbuehler/go-acme-client/requests"
	"github.com/stbuehler/go-acme-client/storage"
	"github.com/stbuehler/go-acme-client/ui"
	"github.com/stbuehler/go-acme-client/utils"
	"strconv"
)

var register_flags = flag.NewFlagSet("register", flag.ExitOnError)

var storagePath string

func init() {
	register_flags.StringVar(&storagePath, "storage", "storage.pem", "Storagefile")
	utils.AddLogFlags(register_flags)
}

func Run(UI ui.UserInterface, args []string) {
	register_flags.Parse(args)

	st, err := storage.LoadStorageFile(storagePath, UI.PasswordPromptOnce("Enter password: "))
	if nil != err {
		utils.Fatalf("Couldn't load the registration: %s", err)
	}

	if nil == st.RegistrationData {
		utils.Fatalf("You need to register first")
	}

	if 1 != len(register_flags.Args()) {
		msg := "The following authorizations are available:\n"
		for _, auth := range st.Authorizations {
			msg += fmt.Sprintf("\t%s (%s)\n", auth.DNSIdentifier, auth.UrlSelf)
		}
		msg += "Provide the domain (or url) you want to work with as command line parameter"
		UI.Message(msg)
		return
	}
	domain := register_flags.Arg(0)

	var auth *requests.Authorization
	{
		var found []*requests.Authorization
		for ndx, auth := range st.Authorizations {
			if auth.DNSIdentifier == domain || auth.UrlSelf == domain {
				found = append(found, &st.Authorizations[ndx])
			}
		}
		if 1 == len(found) {
			auth = found[0]
		} else if 0 < len(found) {
			msg := fmt.Sprintf("The following authorizations for domain %s are available:\n", domain)
			for _, auth := range found {
				msg += fmt.Sprintf("\t%s\n", auth.UrlSelf)
			}
			msg += "Provide the url you want to work with as command line parameter"
			UI.Message(msg)
			return
		}
	}

	if nil == auth {
		newAuth, err := requests.NewDNSAuthorization(st.RegistrationData.UrlAuth, st.RegistrationKey, domain)
		if nil != err {
			utils.Fatalf("Couldn't create authorization for %v: %s", domain, err)
		}
		st.Authorizations = append(st.Authorizations, *newAuth)
		auth = &st.Authorizations[len(st.Authorizations)-1]
	} else {
		if err := auth.Refresh(); nil != err {
			utils.Errorf("Couldn't update authorization: %s", err)
		}
	}
	if err = storage.SaveStorageFile(storagePath, st); nil != err {
		utils.Fatalf("Couldn't save the new authorization: %s", err)
	}

	utils.Debugf("Authorization: %#v", auth)

	msg := fmt.Sprintf("Status: %s\n", auth.Status)
	if string(auth.Status) == "valid" {
		msg += fmt.Sprintf("Expires: %s\n", auth.Expires)
	}

	for ndx, challenge := range auth.Challenges {
		msg += fmt.Sprintf("Challenge: %d\n", ndx)
		msg += fmt.Sprintf("\tType: %s\n", challenge.Type)
		msg += fmt.Sprintf("\tStatus: %s\n", challenge.Status)
		if 0 != len(challenge.Validated) {
			msg += fmt.Sprintf("\tValidated: %s\n", challenge.Validated)
		}
		if 0 != len(challenge.URI) {
			msg += fmt.Sprintf("\tURI: %s\n", challenge.URI)
		}
		if nil != challenge.Data {
			fields, err := challenge.Data.MarshalJSONPartial()
			if nil != err {
				utils.Fatalf("Failed to serialize challenge data: %s", err)
			}
			for field, value := range fields {
				msg += fmt.Sprintf("\t%s: %v\n", field, value)
			}
		}
	}
	msg += fmt.Sprintf("Valid combinations: %v", auth.Combinations)

	UI.Message(msg)

	for {
		sel, err := UI.Prompt("Enter a challenge number to respond to (or enter nothing to exit)")
		if nil != err {
			utils.Fatalf("Failed reading challenge number: %s", err)
		}
		if 0 == len(sel) {
			break
		}
		selCh, err := strconv.Atoi(sel)
		if nil != err {
			UI.Messagef("Invalid input (%s), try again", err)
			continue
		}
		if selCh < 0 || selCh >= len(auth.Challenges) {
			UI.Messagef("Not a valid challenge index, try again", err)
			continue
		}

		challenge := &auth.Challenges[selCh]
		chResp, ok := challenge.Data.(requests.ChallengeResponding)
		if nil == chResp || !ok {
			UI.Messagef("Responding for challenge %d not supported", selCh)
			continue
		}

		if err = chResp.InitializeResponse(auth, UI); nil != err {
			UI.Messagef("Failed to initialize response: %s", err)
		}

		if err = chResp.ShowInstructions(auth, UI); nil != err {
			UI.Messagef("Failed to complete challenge: %s", err)
			continue
		}
		if err = chResp.Verify(auth); nil != err {
			UI.Messagef("Failed to verify challenge: %s", err)
			continue
		}

		if err = challenge.Update(st.RegistrationKey); nil != err {
			UI.Messagef("Failed to update challenge: %s", err)
			continue
		}

		if err := auth.Refresh(); nil != err {
			utils.Errorf("Couldn't update authorization: %s", err)
		}
		if err = storage.SaveStorageFile(storagePath, st); nil != err {
			utils.Fatalf("Couldn't save the new authorization: %s", err)
		}
	}
}
