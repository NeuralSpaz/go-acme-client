package types

import (
	"encoding/json"
	"github.com/stbuehler/go-acme-client/ui"
)

type ChallengeResponding interface {
	ResetResponse() error
	InitializeResponse(UI ui.UserInterface) error
	ShowInstructions(UI ui.UserInterface) error
	Verify() error
	SendPayload() (interface{}, error)
	ChallengeData() ChallengeData
	Challenge() Challenge
	Registration() *Registration
}

type ChallengeImplementation interface {
	GetType() string
	GetStatus() string
	GetValidated() string
	GetURI() string

	initializeResponse(registration *Registration, authorization *Authorization) (ChallengeResponding, error)
}

type Challenge struct {
	chImpl ChallengeImplementation
}

type rawChallengeBasic struct {
	Type      string `json:"type,omitempty"`
	Status    string `json:"status,omitempty"`
	Validated string `json:"validated,omitempty"`
	URI       string `json:"uri,omitempty"`
}

func (authorization *Authorization) Respond(registration Registration, challengeIndex int) (ChallengeResponding, error) {
	challenge := &authorization.Resource.Challenges[challengeIndex]

	return challenge.chImpl.initializeResponse(&registration, authorization)
}

func (challenge *Challenge) UnmarshalJSON(data []byte) error {
	var jsonType struct {
		Type string `json:"type,omitempty"`
	}
	if err := json.Unmarshal(data, &jsonType); nil != err {
		return err
	}

	var newC ChallengeImplementation = &unknownChallenge{}

	switch jsonType.Type {
	case simpleHttpIdentifier:
		newC = &challengeSimpleHttp{}
	case dvsniIdentifier:
		newC = &challengeDVSNI{}
	}

	if err := json.Unmarshal(data, newC); nil != err {
		return err
	}
	challenge.chImpl = newC
	return nil
}

func (challenge *Challenge) MarshalJSON() (data []byte, err error) {
	return json.Marshal(challenge.chImpl)
}

func (challenge *Challenge) GetType() string {
	return challenge.chImpl.GetType()
}

func (challenge *Challenge) GetStatus() string {
	return challenge.chImpl.GetStatus()
}

func (challenge *Challenge) GetValidated() string {
	return challenge.chImpl.GetValidated()
}

func (challenge *Challenge) GetURI() string {
	return challenge.chImpl.GetURI()
}
