package types

import (
	"encoding/json"
	"fmt"
)

type challengeImpl interface {
	merge(json.RawMessage) error                      // merge json response from server
	marshalJSON(challenge *Challenge) ([]byte, error) // marshal complete challenge
}

type Challenge struct {
	challengeImpl challengeImpl
	Type          string
	Status        string
	Validated     string
	URI           string
}

type rawChallengeBasic struct {
	Type      string `json:"type,omitempty"`
	Status    string `json:"status,omitempty"`
	Validated string `json:"validated,omitempty"`
	URI       string `json:"uri,omitempty"`
}

func (challenge *Challenge) Merge(msg json.RawMessage) error {
	var base rawChallengeBasic
	if err := json.Unmarshal([]byte(msg), &base); nil != err {
		return err
	}
	if base.Type != challenge.Type {
		return fmt.Errorf("Updated challenge has wrong type %v, expected %v", base.Type, challenge.Type)
	}
	if 0 != len(base.URI) && base.URI != challenge.URI {
		return fmt.Errorf("Updated challenge has wrong URL %#v, expected %#v", base.URI, challenge.URI)
	}
	if err := challenge.challengeImpl.merge(msg); nil != err {
		return err
	}
	challenge.Status = base.Status
	challenge.Validated = base.Validated
	return nil
}

func (authorization *Authorization) Respond(challengeIndex int) *ChallengeResponding {
	challenge := &authorization.Challenges[challengeIndex]
	respImpl, ok := challenge.challengeImpl.(challengeResponseImpl)
	if nil == respImpl || !ok {
		return nil
	}
	return &ChallengeResponding{
		authorization:         authorization,
		challenge:             challenge,
		challengeResponseImpl: respImpl,
	}
}

func (challenge *Challenge) UnmarshalJSON(data []byte) error {
	var base rawChallengeBasic
	if err := json.Unmarshal(data, &base); nil != err {
		return err
	}

	challenge.Type = base.Type
	challenge.Status = base.Status
	challenge.Validated = base.Validated
	challenge.URI = base.URI
	challenge.challengeImpl = &FixedChallenge{}
	if 0 != len(challenge.URI) {
		switch base.Type {
		case "simpleHttps":
			challenge.challengeImpl = challengeResponseImpl(&SimpleHttps{})
		case "dvsni":
			challenge.challengeImpl = challengeResponseImpl(&DVSNI{})
		}
	}

	return challenge.challengeImpl.merge(json.RawMessage(data))
}

func (challenge *Challenge) MarshalJSON() (data []byte, err error) {
	return challenge.challengeImpl.marshalJSON(challenge)
}

// unknown challenges / challenges which don't have a URI anymore
type FixedChallenge struct {
	jsonData map[string]interface{}
}

func (chImpl *FixedChallenge) merge(msg json.RawMessage) error {
	return json.Unmarshal([]byte(msg), &chImpl.jsonData)
}

func (chImpl *FixedChallenge) updateInternals(challenge *Challenge) {
	set := func(k, v string) {
		if 0 == len(v) {
			delete(chImpl.jsonData, k)
		} else {
			chImpl.jsonData[k] = v
		}
	}
	set("type", challenge.Type)
	set("status", challenge.Status)
	set("validated", challenge.Validated)
	set("uri", challenge.URI)
}

func (chImpl *FixedChallenge) marshalJSON(challenge *Challenge) ([]byte, error) {
	chImpl.updateInternals(challenge)
	return json.Marshal(chImpl.jsonData)
}
