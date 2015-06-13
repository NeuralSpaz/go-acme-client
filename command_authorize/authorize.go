package command_authorize

import (
	"flag"
	"fmt"
	"github.com/stbuehler/go-acme-client/requests"
	"github.com/stbuehler/go-acme-client/storage"
	"github.com/stbuehler/go-acme-client/types"
	"github.com/stbuehler/go-acme-client/ui"
	"github.com/stbuehler/go-acme-client/utils"
	"strconv"
)

var register_flags = flag.NewFlagSet("register", flag.ExitOnError)

func init() {
	storage.AddStorageFlags(register_flags)
	utils.AddLogFlags(register_flags)
}

func Run(UI ui.UserInterface, args []string) {
	register_flags.Parse(args)

	_, reg := storage.OpenStorageFromFlags(UI)
	if nil == reg {
		utils.Fatalf("You need to register first")
	}

	if 1 != len(register_flags.Args()) {
		auths, err := reg.AuthorizationList()
		if nil != err {
			utils.Fatalf("Couldn't retrieve list fo authorizations: %s", err)
		}
		msg := "The following authorizations are available:\n"
		for dnsName, auth := range auths {
			msg += fmt.Sprintf("\t%s\n", dnsName)
			for _, info := range auth {
				if info.Status == types.AuthorizationStatus("valid") && nil != info.Expires {
					msg += fmt.Sprintf("\t\t%s (%s till %s)\n", info.Location, info.Status, info.Expires)
				} else {
					msg += fmt.Sprintf("\t\t%s (%s)\n", info.Location, info.Status)
				}
			}
		}
		msg += "Provide the domain (or url) you want to work with as command line parameter"
		UI.Message(msg)
		return
	}
	locationOrDnsName := register_flags.Arg(0)

	auth, err := reg.LoadAuthorization(locationOrDnsName)
	if nil != err {
		utils.Fatalf("Couldn't lookup authorization %v: %v", locationOrDnsName, err)
	}

	if nil == auth {
		newAuth, err := requests.NewDNSAuthorization(reg.Registration.LinkAuth, reg.SigningKey, locationOrDnsName)
		if nil != err {
			utils.Fatalf("Couldn't create authorization for %v: %s", locationOrDnsName, err)
		}
		auth, err = reg.NewAuthorization(*newAuth)
		if nil != err {
			utils.Fatalf("Couldn't save the new authorization for %v: %s", locationOrDnsName, err)
		}
	} else {
		if err := requests.RefreshAuthorization(&auth.Authorization); nil != err {
			utils.Errorf("Couldn't update authorization: %s", err)
		}
		if err = auth.Save(); nil != err {
			utils.Fatalf("Couldn't save the updated authorization: %s", err)
		}
	}

	utils.Debugf("Authorization: %#v", auth.Authorization)

	for {
		msg := fmt.Sprintf("Status: %s\n", auth.Authorization.Status)
		if string(auth.Authorization.Status) == "valid" {
			msg += fmt.Sprintf("Expires: %s\n", auth.Authorization.Expires)
		}
		for ndx, challenge := range auth.Authorization.Challenges {
			if 0 != len(challenge.Validated) {
				msg += fmt.Sprintf("Challenge: %d (%s, %s, validated on %s)\n", ndx, challenge.Type, challenge.Status, challenge.Validated)
			} else {
				msg += fmt.Sprintf("Challenge: %d (%s, %s)\n", ndx, challenge.Type, challenge.Status)
			}
		}
		msg += fmt.Sprintf("Valid combinations: %v", auth.Authorization.Combinations)
		UI.Message(msg)

		if 0 != len(auth.Authorization.Status) {
			UI.Message("Authorization finished")
			return
		}

		sel, err := UI.Prompt("Enter a challenge number to respond to (or r for refresh and empty string to exit)")
		if nil != err {
			utils.Fatalf("Failed reading challenge number: %s", err)
		}
		if 0 == len(sel) {
			break
		}
		if sel != "r" {
			selCh, err := strconv.Atoi(sel)
			if nil != err {
				UI.Messagef("Invalid input (%s), try again", err)
				continue
			}
			if selCh < 0 || selCh >= len(auth.Authorization.Challenges) {
				UI.Messagef("Not a valid challenge index, try again", err)
				continue
			}

			chResp := auth.Authorization.Respond(selCh)
			if nil == chResp {
				UI.Messagef("Responding for challenge %d not supported", selCh)
				continue
			}

			if err = chResp.InitializeResponse(UI); nil != err {
				UI.Messagef("Failed to initialize response: %s", err)
			}

			if err = chResp.ShowInstructions(UI); nil != err {
				UI.Messagef("Failed to complete challenge: %s", err)
				continue
			}
			if err = chResp.Verify(); nil != err {
				UI.Messagef("Failed to verify challenge: %s", err)
				continue
			}

			if err = requests.UpdateChallenge(chResp, reg.SigningKey); nil != err {
				UI.Messagef("Failed to update challenge: %s", err)
				continue
			}
		}

		if err := requests.RefreshAuthorization(&auth.Authorization); nil != err {
			utils.Errorf("Couldn't update authorization: %s", err)
		} else if err = auth.Save(); nil != err {
			utils.Fatalf("Couldn't save the updated authorization: %s", err)
		}
	}
}
