package types

import (
	"github.com/stbuehler/go-acme-client/ui"
)

type challengeResponseImpl interface {
	challengeImpl
	resetResponse()                                                        // clear fields set by the client
	initializeResponse(*Authorization, *Challenge, ui.UserInterface) error // set some fields, maybe ask the client about them
	showInstructions(*Authorization, *Challenge, ui.UserInterface) error   // show instructions to provide response for challenge
	verify(*Authorization, *Challenge) error                               // verify pending response
	sendPayload(*Authorization, *Challenge) (interface{}, error)           // payload to update challenge
}

type ChallengeResponding struct {
	authorization         *Authorization
	challenge             *Challenge
	challengeResponseImpl challengeResponseImpl
}

func (resp ChallengeResponding) Authorization() *Authorization {
	return resp.authorization
}

func (resp ChallengeResponding) Challenge() *Challenge {
	return resp.challenge
}

func (resp ChallengeResponding) ResetResponse() {
	resp.challengeResponseImpl.resetResponse()
}

func (resp ChallengeResponding) InitializeResponse(UI ui.UserInterface) error {
	return resp.challengeResponseImpl.initializeResponse(resp.authorization, resp.challenge, UI)
}

func (resp ChallengeResponding) ShowInstructions(UI ui.UserInterface) error {
	return resp.challengeResponseImpl.showInstructions(resp.authorization, resp.challenge, UI)
}

func (resp ChallengeResponding) Verify() error {
	return resp.challengeResponseImpl.verify(resp.authorization, resp.challenge)
}

func (resp ChallengeResponding) SendPayload() (interface{}, error) {
	return resp.challengeResponseImpl.sendPayload(resp.authorization, resp.challenge)
}
