package types

import (
	"encoding/json"
)

type unknownChallenge struct {
	basic rawChallengeBasic
	data  map[string]interface{}
}

func (c *unknownChallenge) MarshalJSON() ([]byte, error) {
	c.data["resource"] = Resource_Challenge.String()
	return json.Marshal(c.data)
}

func (c *unknownChallenge) UnmarshalJSON(data []byte) error {
	var result unknownChallenge
	if err := json.Unmarshal(data, &result.basic); nil != err {
		return err
	} else if err := json.Unmarshal(data, &result.data); nil != err {
		return err
	} else {
		*c = result
		return nil
	}
}

func (c *unknownChallenge) GetType() string {
	return c.basic.Type
}

func (c *unknownChallenge) GetStatus() string {
	return c.basic.Status
}

func (c *unknownChallenge) GetValidated() string {
	return c.basic.Validated
}

func (c *unknownChallenge) GetURI() string {
	return c.basic.URI
}

func (*unknownChallenge) initializeResponse(registration *Registration, authorization *Authorization) (ChallengeResponding, error) {
	return nil, nil
}
