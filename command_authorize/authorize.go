package command_authorize

import (
	"flag"
	"fmt"
	"github.com/stbuehler/go-acme-client/command_base"
	"github.com/stbuehler/go-acme-client/types"
	"github.com/stbuehler/go-acme-client/ui"
	"github.com/stbuehler/go-acme-client/utils"
	"strconv"
)

var register_flags = flag.NewFlagSet("register", flag.ExitOnError)

func init() {
	command_base.AddStorageFlags(register_flags)
	utils.AddLogFlags(register_flags)
}

func Run(UI ui.UserInterface, args []string) {
	register_flags.Parse(args)

	_, _, reg := command_base.OpenStorageFromFlags(UI)
	if nil == reg {
		utils.Fatalf("You need to register first")
	}

	if 1 != len(register_flags.Args()) {
		auths, err := reg.AuthorizationInfos()
		if nil != err {
			utils.Fatalf("Couldn't retrieve list of authorizations: %s", err)
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

	auth, err := reg.LoadAuthorizationByURL(locationOrDnsName)
	if nil != err {
		utils.Fatalf("Couldn't load authorization %v: %v", locationOrDnsName, err)
	} else if nil != auth {
		if err := auth.Refresh(); nil != err {
			utils.Fatalf("Couldn't refresh authorization %v: %v", locationOrDnsName, err)
		}
	} else {
		if auth, err = reg.AuthorizeDNS(locationOrDnsName); nil != err {
			utils.Fatalf("Couldn't get authorization for %v: %s", locationOrDnsName, err)
		}
	}

	for {
		// refresh every round
		authData := auth.Authorization()

		msg := fmt.Sprintf("Status: %s\n", authData.Resource.Status)
		if string(authData.Resource.Status) == "valid" {
			msg += fmt.Sprintf("Expires: %s\n", authData.Resource.Expires)
		}
		for ndx, challenge := range authData.Resource.Challenges {
			if 0 != len(challenge.GetValidated()) {
				msg += fmt.Sprintf("Challenge: %d (%s, %s, validated on %s)\n", ndx, challenge.GetType(), challenge.GetStatus(), challenge.GetValidated())
			} else {
				msg += fmt.Sprintf("Challenge: %d (%s, %s)\n", ndx, challenge.GetType(), challenge.GetStatus())
			}
		}
		msg += fmt.Sprintf("Valid combinations: %v", authData.Resource.Combinations)
		UI.Message(msg)

		if 0 != len(authData.Resource.Status) {
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
			if selCh < 0 || selCh >= len(authData.Resource.Challenges) {
				UI.Messagef("Not a valid challenge index, try again", err)
				continue
			}

			chResp, err := authData.Respond(reg.Registration(), selCh)
			if nil != err {
				utils.Fatalf("Error trying to create response: %s", err)
			}
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
				if err = auth.SaveChallengeData(chResp); nil != err {
					utils.Fatalf("Couldn't store challenge data: %s", err)
				}
				continue
			}

			// update refreshes auth automatically
			if err = auth.UpdateChallenge(chResp); nil != err {
				UI.Messagef("Failed to update challenge: %s", err)
				continue
			}
		} else {
			if err := auth.Refresh(); nil != err {
				utils.Errorf("Couldn't update authorization: %s", err)
			}
		}
	}
}
