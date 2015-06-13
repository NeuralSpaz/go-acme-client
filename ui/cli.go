package ui

import (
	"bufio"
	"os"
	"strings"
)

type cli struct {
}

var CLI UserInterface = cli{}

var cli_bufStdin *bufio.Reader

func InitCLI() {
	cli_bufStdin = bufio.NewReader(os.Stdin)
}

func promptAndReadLine(prompt string) (string, error) {
	print(prompt + ": ")
	input, err := cli_bufStdin.ReadString('\n')
	input = strings.TrimSpace(input)
	return input, err
}

func (cli) Prompt(prompt string) (string, error) {
	return promptAndReadLine(prompt)
}

func (cli) NewPasswordPrompt(first string, second string) (string, error) {
	for {
		pw1, err := promptAndReadLine(first)
		if nil != err {
			return "", err
		}
		if 0 != len(pw1) {
			pw2, err := promptAndReadLine(second)
			if nil != err {
				return "", err
			}
			if pw1 != pw2 {
				println("Passwords didn't match, try again")
				continue
			}
		}
		return pw1, nil
	}
}

func (cli) PasswordPrompt(prompt string) (string, error) {
	return promptAndReadLine(prompt)
}

func (cli) FormInput(title string, fields []string) ([]string, error) {
	if 0 != len(title) {
		println(title)
	}
	values := make([]string, len(fields))
	for ndx, field := range fields {
		var err error
		if values[ndx], err = promptAndReadLine(field); nil != err {
			return nil, err
		}
	}
	return values, nil
}

func (cli) YesNoDialog(title string, text string, prompt string, def bool) (bool, error) {
	if 0 != len(title) {
		println(title)
	}
	if 0 != len(text) {
		println(text)
	}

	for {
		var ans string
		var err error
		if def {
			ans, err = promptAndReadLine(prompt + " [Y/n] ")
		} else {
			ans, err = promptAndReadLine(prompt + " [y/N] ")
		}
		if nil != err {
			return def, err
		}
		switch strings.ToLower(ans) {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		case "":
			return def, nil
		default:
			println("Invalid answer, try again")
		}
	}
}

func (cli) Message(text string) {
	println(text)
}

func (cli) Messagef(format string, v ...interface{}) {
	Messagef(CLI, format, v...)
}
func (cli) PasswordPromptOnce(prompt string) func() (string, error) {
	return PasswordPromptOnce(CLI, prompt)
}
