package command_register

import (
	"github.com/stbuehler/go-acme-client/ui"
)

type contactMeta struct {
	uri  string // uri prefix
	desc string
}

var contactMetaEntries = []contactMeta{
	contactMeta{
		uri:  "mailto:",
		desc: "email address",
	},
	contactMeta{
		uri:  "tel:",
		desc: "phone number",
	},
}

func EnterNewContact(UI ui.UserInterface) ([]string, error) {
	var fields = []string{
		"email address",
		"phone number",
	}
	var uris = []string{
		"mailto:",
		"tel:",
	}

	var contacts []string

	values, err := UI.FormInput("Enter contact data, leave fields empty to omit them", fields)
	if err != nil {
		return nil, err
	}
	for ndx, value := range values {
		if 0 != len(value) {
			contacts = append(contacts, uris[ndx]+value)
		}
	}

	return contacts, nil
}
