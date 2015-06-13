package ui

import (
	"fmt"
)

type UserInterface interface {
	Prompt(string) (string, error)

	NewPasswordPrompt(string, string) (string, error)
	PasswordPrompt(string) (string, error)

	FormInput(title string, fields []string) ([]string, error)

	YesNoDialog(title string, text string, prompt string, def bool) (bool, error)

	Message(text string)

	// common implementations based on functions above below
	Messagef(format string, v ...interface{})
	PasswordPromptOnce(prompt string) func() (string, error)
}

func Messagef(UI UserInterface, format string, v ...interface{}) {
	UI.Message(fmt.Sprintf(format, v...))
}

func PasswordPromptOnce(UI UserInterface, prompt string) func() (string, error) {
	var password *string
	var err *error

	return func() (string, error) {
		if nil != password {
			return *password, nil
		} else if nil != err {
			return "", *err
		} else if p, e := UI.PasswordPrompt(prompt); nil != e {
			err = &e
			return "", e
		} else {
			password = &p
			return p, nil
		}
	}
}
